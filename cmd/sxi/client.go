package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/godbus/dbus/v5"
)

const (
	busName    = "dev.sinty.SXI1"
	objectPath = dbus.ObjectPath("/dev/sinty/SXI1")
)

func daemon() (*dbus.Conn, dbus.BusObject, error) {
	if os.Getenv("DBUS_SYSTEM_BUS_ADDRESS") == "" {
		os.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/run/dbus/system_bus_socket")
	}
	connect := dbus.ConnectSystemBus
	if os.Getenv("SXI_BUS") == "session" {
		connect = dbus.ConnectSessionBus
	}
	conn, err := connect()
	if err != nil {
		return nil, nil, err
	}
	return conn, conn.Object(busName, objectPath), nil
}

func list(args []string) error {
	installed := len(args) == 1 && args[0] == "-installed"
	conn, obj, err := daemon()
	if err != nil {
		return err
	}
	defer conn.Close()
	method := busName + ".ListAvailable"
	if installed {
		method = busName + ".ListInstalled"
	}
	var data string
	if err := obj.Call(method, 0).Store(&data); err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	defer w.Flush()
	if installed {
		var apps []struct {
			ID     string `json:"id"`
			Name   string `json:"name"`
			Source string `json:"source"`
			Active struct {
				Version  string `json:"version"`
				Sequence uint64 `json:"sequence"`
			} `json:"active"`
			Previous *struct {
				Version string `json:"version"`
			} `json:"previous"`
		}
		if err := json.Unmarshal([]byte(data), &apps); err != nil {
			return err
		}
		fmt.Fprintln(w, "ID\tNAME\tVERSION\tPREVIOUS\tSOURCE")
		for _, a := range apps {
			previous := "-"
			if a.Previous != nil {
				previous = a.Previous.Version
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", a.ID, a.Name, a.Active.Version, previous, a.Source)
		}
		return nil
	}
	var apps []struct {
		ID       string `json:"id"`
		Name     string `json:"name"`
		Source   string `json:"source"`
		Releases []struct {
			Version string `json:"version"`
		} `json:"releases"`
		Installed *struct {
			Version string `json:"version"`
		} `json:"installed"`
	}
	if err := json.Unmarshal([]byte(data), &apps); err != nil {
		return err
	}
	fmt.Fprintln(w, "ID\tNAME\tLATEST\tINSTALLED\tSOURCE")
	for _, a := range apps {
		latest, installed := "-", "-"
		if len(a.Releases) > 0 {
			latest = a.Releases[0].Version
		}
		if a.Installed != nil {
			installed = a.Installed.Version
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", a.ID, a.Name, latest, installed, a.Source)
	}
	return nil
}

func refresh(args []string) error {
	conn, obj, err := daemon()
	if err != nil {
		return err
	}
	defer conn.Close()
	return obj.Call(busName+".Refresh", 0).Err
}

func waitFor(method string) func([]string) error {
	return func(args []string) error {
		if len(args) != 1 {
			return fmt.Errorf("%s: one application id is required", method)
		}
		id := args[0]
		conn, obj, err := daemon()
		if err != nil {
			return err
		}
		defer conn.Close()
		if err := conn.AddMatchSignal(dbus.WithMatchObjectPath(objectPath), dbus.WithMatchInterface(busName)); err != nil {
			return err
		}
		signals := make(chan *dbus.Signal, 64)
		conn.Signal(signals)
		if err := obj.Call(busName+"."+method, 0, id).Err; err != nil {
			return err
		}
		if method != "Install" {
			return nil
		}
		progressed := false
		for sig := range signals {
			switch sig.Name {
			case busName + ".Progress":
				if len(sig.Body) == 4 && sig.Body[0] == id {
					fmt.Fprintf(os.Stderr, "\r%s %v/%v   ", sig.Body[1], sig.Body[2], sig.Body[3])
					progressed = true
				}
			case busName + ".Finished":
				if len(sig.Body) == 2 && sig.Body[0] == id {
					if progressed {
						fmt.Fprintln(os.Stderr)
					}
					if message, _ := sig.Body[1].(string); message != "" {
						return errors.New(message)
					}
					fmt.Println("installed", id)
					return nil
				}
			}
		}
		return errors.New("the daemon went away")
	}
}
