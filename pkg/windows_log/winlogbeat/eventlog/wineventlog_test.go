package eventlog

import (
	"bytes"
	"d-eyes/pkg/windows_log/winlogbeat/sys"
	"d-eyes/pkg/windows_log/winlogbeat/sys/winevent"
	win "d-eyes/pkg/windows_log/winlogbeat/sys/wineventlog"
	"encoding/xml"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func TestWinEventLogByFile(t *testing.T) {

	evtx, err := filepath.Abs("C:\\Windows\\System32\\winevt\\Logs\\System.evtx")

	if err != nil {
		t.Fatal(err)
	}
	// Open .evtx file.
	h, err := win.EvtQuery(0, evtx, "", win.EvtQueryFilePath|win.EvtQueryReverseDirection)
	if err != nil {
		t.Fatal(err)
	}
	defer win.Close(h) //nolint:errcheck // This is just a resource release.

	// Get handles to events.
	buf := make([]byte, 32*1024)
	var out io.Writer

	out = &bytes.Buffer{}

	eventMetadataHandle := func(providerName, sourceName string) sys.MessageFiles {
		mf := sys.MessageFiles{SourceName: sourceName}
		h, err := win.OpenPublisherMetadata(0, sourceName, 0)
		if err != nil {
			mf.Err = err
			return mf
		}

		mf.Handles = []sys.FileHandle{{Handle: uintptr(h)}}
		return mf
	}

	freeHandle := func(handle uintptr) error {
		return win.Close(win.EvtHandle(handle))
	}

	cache := newMessageFilesCache("C:\\Windows\\System32\\winevt\\Logs\\System.evtx", eventMetadataHandle, freeHandle)

	var count int
	for {
		handles, err := win.EventHandles(h, 8)
		if err == win.ERROR_NO_MORE_ITEMS { //nolint:errorlint // This is never wrapped.
			t.Log(err)
			break
		}
		if err != nil {
			t.Fatal(err)
		}

		// Read events.
		for _, h := range handles {
			//win.RenderEventXML(h, buf, out)
			if err = win.RenderEvent(h,0, buf, cache.get, out); err != nil {
				t.Fatal(err)
			}
			win.Close(h) //nolint:errcheck // This is just a resource release.
			fmt.Fprintln(out)
			count++
		}
		if count == 8 {
			break
		}
	}


	got, err := unmarshalXMLEvents(out.(*bytes.Buffer))
	if err != nil {
		t.Fatalf("failed to unmarshal obtained events: %v", err)
	}
	for i, g := range got {
		fmt.Println("**************************************")
		fmt.Println(g.Message)
		fmt.Println(g.TimeCreated)
		if i > 10 {
			break
		}
	}

	fmt.Println("events:", count)

}

// unmarshalXMLEvents unmarshals a complete set of events from the XML data
// in the provided io.Reader. GUID values are canonicalised to lowercase.
func unmarshalXMLEvents(r io.Reader) ([]winevent.Event, error) {
	var events []winevent.Event
	decoder := xml.NewDecoder(r)
	for {
		var e winevent.Event
		err := decoder.Decode(&e)
		if err != nil {
			if err != io.EOF { //nolint:errorlint // This is never wrapped.
				return nil, err
			}
			break
		}
		events = append(events, canonical(e))
	}
	return events, nil
}

// canonical return e with its GUID values canonicalised to lower case.
// Different versions of Windows render these values in different cases; ¯\_(ツ)_/¯
func canonical(e winevent.Event) winevent.Event {
	e.Provider.GUID = strings.ToLower(e.Provider.GUID)
	for i, kv := range e.EventData.Pairs {
		if strings.Contains(strings.ToLower(kv.Key), "guid") {
			e.EventData.Pairs[i].Value = strings.ToLower(kv.Value)
		}
	}
	return e
}

