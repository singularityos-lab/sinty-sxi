package manager

import (
	"errors"
	"testing"
)

func TestCheckSchema(t *testing.T) {
	good := `<schemalist>
  <enum id="dev.sinty.hello.Mode"><value nick="a" value="0"/></enum>
  <schema id="dev.sinty.hello" path="/dev/sinty/hello/">
    <key name="greeting" type="s"><default>'hi'</default></key>
  </schema>
  <schema id="dev.sinty.hello.window" path="/dev/sinty/hello/window/"/>
</schemalist>`
	if err := checkSchema("dev.sinty.hello", []byte(good)); err != nil {
		t.Fatal(err)
	}
	bad := map[string]string{
		"foreign id":      `<schemalist><schema id="dev.sinty.desktop" path="/dev/sinty/hello/"/></schemalist>`,
		"lookalike id":    `<schemalist><schema id="dev.sinty.hellothere" path="/dev/sinty/hello/"/></schemalist>`,
		"foreign path":    `<schemalist><schema id="dev.sinty.hello" path="/dev/sinty/desktop/"/></schemalist>`,
		"foreign enum":    `<schemalist><enum id="org.gnome.Mode"/></schemalist>`,
		"foreign extends": `<schemalist><schema id="dev.sinty.hello.x" extends="dev.sinty.desktop"/></schemalist>`,
	}
	for name, schema := range bad {
		if err := checkSchema("dev.sinty.hello", []byte(schema)); !errors.Is(err, ErrSchema) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	if err := checkSchema("dev.sinty.hello", []byte("<schemalist><schema")); err == nil {
		t.Error("broken XML accepted")
	}
}
