package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"

	"github.com/singularityos-lab/sinty-sxi/manager"
)

const (
	busName       = "dev.sinty.SXI1"
	objectPath    = dbus.ObjectPath("/dev/sinty/SXI1")
	interfaceName = "dev.sinty.SXI1"
	uidMin        = 1000
	uidMax        = 60000
	systemSources = "/usr/share/sinty/sxi/sources.d"
)

type service struct {
	conn    *dbus.Conn
	manager *manager.Manager
	mu      sync.Mutex
	busy    map[string]bool
}

func loadSources(dirs ...string) ([]manager.Source, error) {
	byName := map[string]manager.Source{}
	for _, dir := range dirs {
		names, _ := filepath.Glob(filepath.Join(dir, "*.json"))
		sort.Strings(names)
		for _, name := range names {
			data, err := os.ReadFile(name)
			if err != nil {
				return nil, err
			}
			var src manager.Source
			if err := json.Unmarshal(data, &src); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if src.Name == "" || src.URL == "" {
				return nil, fmt.Errorf("%s: name and url are required", name)
			}
			if dir != systemSources {
				src.Official = false
			}
			byName[src.Name] = src
		}
	}
	out := make([]manager.Source, 0, len(byName))
	for _, src := range byName {
		out = append(out, src)
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out, nil
}

func denied(action string, uid uint32) *dbus.Error {
	return dbus.NewError("org.freedesktop.DBus.Error.AccessDenied", []interface{}{fmt.Sprintf("not authorized to %s (caller uid %d)", action, uid)})
}

func failed(err error) *dbus.Error {
	return dbus.NewError("dev.sinty.SXI1.Error.Failed", []interface{}{err.Error()})
}

func (s *service) authorize(sender dbus.Sender, action string) *dbus.Error {
	var uid uint32
	if err := s.conn.BusObject().Call("org.freedesktop.DBus.GetConnectionUnixUser", 0, string(sender)).Store(&uid); err != nil {
		return failed(err)
	}
	if uid == 0 || (uid >= uidMin && uid < uidMax) {
		return nil
	}
	return denied(action, uid)
}

func (s *service) changed() {
	s.conn.Emit(objectPath, interfaceName+".Changed")
}

func (s *service) ListAvailable() (string, *dbus.Error) {
	data, err := json.Marshal(s.manager.Available())
	if err != nil {
		return "", failed(err)
	}
	return string(data), nil
}

func (s *service) ListInstalled() (string, *dbus.Error) {
	data, err := json.Marshal(s.manager.Installed())
	if err != nil {
		return "", failed(err)
	}
	return string(data), nil
}

func (s *service) Refresh(sender dbus.Sender) *dbus.Error {
	if err := s.authorize(sender, "refresh the collections"); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	err := s.manager.Refresh(ctx)
	s.changed()
	if err != nil {
		return failed(err)
	}
	return nil
}

func (s *service) start(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.busy[id] {
		return false
	}
	s.busy[id] = true
	return true
}

func (s *service) done(id string, err error) {
	s.mu.Lock()
	delete(s.busy, id)
	s.mu.Unlock()
	message := ""
	if err != nil {
		message = err.Error()
		log.Printf("%s: %v", id, err)
	}
	s.conn.Emit(objectPath, interfaceName+".Finished", id, message)
	s.changed()
}

func (s *service) Install(sender dbus.Sender, id string) *dbus.Error {
	if err := s.authorize(sender, "install applications"); err != nil {
		return err
	}
	if !s.start(id) {
		return failed(errors.New("an operation on this application is already running"))
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
		defer cancel()
		last := time.Time{}
		err := s.manager.Install(ctx, id, func(stage string, done, total int64) {
			if time.Since(last) < 200*time.Millisecond && done != total {
				return
			}
			last = time.Now()
			s.conn.Emit(objectPath, interfaceName+".Progress", id, stage, done, total)
		})
		s.done(id, err)
	}()
	return nil
}

func (s *service) Remove(sender dbus.Sender, id string) *dbus.Error {
	if err := s.authorize(sender, "remove applications"); err != nil {
		return err
	}
	if !s.start(id) {
		return failed(errors.New("an operation on this application is already running"))
	}
	err := s.manager.Remove(id)
	s.done(id, err)
	if err != nil {
		return failed(err)
	}
	return nil
}

func (s *service) Rollback(sender dbus.Sender, id string) *dbus.Error {
	if err := s.authorize(sender, "roll back applications"); err != nil {
		return err
	}
	if !s.start(id) {
		return failed(errors.New("an operation on this application is already running"))
	}
	err := s.manager.Rollback(id)
	s.done(id, err)
	if err != nil {
		return failed(err)
	}
	return nil
}

func introspection() *introspect.Node {
	str := func(name string) introspect.Arg { return introspect.Arg{Name: name, Type: "s", Direction: "in"} }
	out := func(name string) introspect.Arg { return introspect.Arg{Name: name, Type: "s", Direction: "out"} }
	return &introspect.Node{
		Name: string(objectPath),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name: interfaceName,
				Methods: []introspect.Method{
					{Name: "ListAvailable", Args: []introspect.Arg{out("apps")}},
					{Name: "ListInstalled", Args: []introspect.Arg{out("apps")}},
					{Name: "Refresh"},
					{Name: "Install", Args: []introspect.Arg{str("id")}},
					{Name: "Remove", Args: []introspect.Arg{str("id")}},
					{Name: "Rollback", Args: []introspect.Arg{str("id")}},
				},
				Signals: []introspect.Signal{
					{Name: "Changed"},
					{Name: "Progress", Args: []introspect.Arg{{Name: "id", Type: "s"}, {Name: "stage", Type: "s"}, {Name: "done", Type: "x"}, {Name: "total", Type: "x"}}},
					{Name: "Finished", Args: []introspect.Arg{{Name: "id", Type: "s"}, {Name: "error", Type: "s"}}},
				},
			},
		},
	}
}

func main() {
	roots := flag.String("roots", "/usr/share/sinty/sxi/roots", "trusted publisher roots")
	state := flag.String("state", "/var/lib/sinty/sxi", "state directory")
	run := flag.String("run", "/run/sxi", "runtime directory")
	interval := flag.Duration("refresh", 6*time.Hour, "collection refresh interval, 0 disables")
	sources := flag.String("sources", "", "extra directory of collection sources")
	session := flag.Bool("session", false, "serve on the session bus, for development")
	extract := flag.Bool("extract", false, "extract images instead of mounting them, for development without root")
	flag.Parse()
	log.SetFlags(0)
	dirs := []string{systemSources, "/etc/sinty/sxi/sources.d"}
	if *sources != "" {
		dirs = append(dirs, *sources)
	}
	list, err := loadSources(dirs...)
	if err != nil {
		log.Fatal(err)
	}
	cfg := manager.Config{Roots: *roots, State: *state, Run: *run, Sources: list}
	if *extract {
		cfg.Mounter = &manager.ExtractMounter{}
	}
	m, err := manager.New(cfg)
	if err != nil {
		log.Fatal(err)
	}
	if err := m.Start(); err != nil {
		log.Printf("start: %v", err)
	}
	connect := dbus.ConnectSystemBus
	if *session {
		connect = dbus.ConnectSessionBus
	}
	conn, err := connect()
	if err != nil {
		log.Fatal(err)
	}
	s := &service{conn: conn, manager: m, busy: map[string]bool{}}
	if err := conn.Export(s, objectPath, interfaceName); err != nil {
		log.Fatal(err)
	}
	if err := conn.Export(introspect.NewIntrospectable(introspection()), objectPath, "org.freedesktop.DBus.Introspectable"); err != nil {
		log.Fatal(err)
	}
	reply, err := conn.RequestName(busName, dbus.NameFlagDoNotQueue)
	if err != nil {
		log.Fatal(err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("%s is owned by another process", busName)
	}
	refresh := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		if err := m.Refresh(ctx); err != nil {
			log.Printf("refresh: %v", err)
		}
		s.changed()
	}
	if *interval > 0 {
		go func() {
			refresh()
			for range time.Tick(*interval) {
				refresh()
			}
		}()
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	<-signals
}
