package main

import (
	"database/sql"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"log"
	"os"

	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"

	"encoding/base64"
	proto "github.com/golang/protobuf/proto"
	_ "github.com/michaelritsema/ziften-event-forwarder/msg"
	"io"

	"reflect"
	"strings"

	"bytes"
	"crypto/tls"
	"io/ioutil"

	"crypto/md5"
	"net/http"
	"sync"
	"time"
)

func WindowsTimeToUnixTime(windows_time int64) int64 {
	// number of milliseconds between Jan 1st 1601 and Jan 1st 1970
	var time_shift int64
	time_shift = 11644473600000

	if windows_time == 0 {
		return windows_time
	}

	windows_time /= 10000      // ns to ms
	windows_time -= time_shift // since 1601 to since 1970
	windows_time /= 1000
	return windows_time
}

func WindowsTimeToGoTime(windows_time int64) time.Time {
	// number of milliseconds between Jan 1st 1601 and Jan 1st 1970
	var time_shift int64
	time_shift = 11644473600000

	if windows_time == 0 {
		return time.Unix(0, 0)
	}

	windows_time /= 10000      // ns to ms
	windows_time -= time_shift // since 1601 to since 1970
	windows_time /= 1000
	return time.Unix(windows_time, 0)
}

func UnixToWindowsTime(unix_time int64) int64 {
	// number of milliseconds between Jan 1st 1601 and Jan 1st 1970
	return (unix_time * 10000000) + 116444736000000000

}

/*
CREATE TABLE queue ( msgid INTEGER PRIMARY KEY, queuetag TEXT, msgtag TEXT, body BLOB, ts_created TIMESTAMP, ttl INTEGER, fname TEXT, contentkey BLOB );
*/

func newUUID() (string, error) {
	uuid := make([]byte, 16)
	n, err := io.ReadFull(rand.Reader, uuid)
	if n != len(uuid) || err != nil {
		return "", err
	}
	// variant bits; see section 4.1.1
	uuid[8] = uuid[8]&^0xc0 | 0x80
	// version 4 (pseudo-random); see section 4.1.3
	uuid[6] = uuid[6]&^0xf0 | 0x40
	return strings.ToUpper("{" + fmt.Sprintf("%x-%x-%x-%x-%x", uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]) + "}"), nil
}

// Offset all dates by current time
func adjust(m proto.Message, offset time.Duration) {
	ts := *(reflect.ValueOf(m.(proto.Message)).Elem().FieldByName("TimeStamp").Interface().(*int64))
	originalGoTime := WindowsTimeToGoTime(ts)
	newGoTime := originalGoTime.Add(offset)
	newTimeStamp := newGoTime.Unix()
	//fmt.Printf("Adding %v to %v to get %v\n", offset, originalGoTime, newGoTime)

	reflect.ValueOf(m).Elem().FieldByName("TimeStamp").Set(reflect.ValueOf(proto.Int64(UnixToWindowsTime(newTimeStamp))))

}

func adjustGUID(msgTag string, m proto.Message, guid string) {
	if msgTag == "SystemInventory" {
		reflect.ValueOf(m).Elem().FieldByName("ComputerName").Set(reflect.ValueOf(proto.String(guid)))
	}
	reflect.ValueOf(m).Elem().FieldByName("AgentGUID").Set(reflect.ValueOf(proto.String(guid)))
	siteid := fmt.Sprintf("%x", md5.Sum([]byte("a04.cloud.ziften.com")))
	reflect.ValueOf(m).Elem().FieldByName("SiteId").Set(reflect.ValueOf(proto.String(siteid)))
}

/*

type AgentXMLMessage struct {
	XMLName     xml.Name `xml:"pb"`
	Payload     string   `xml:",chardata"`
	MessageType string   `xml:"type,attr"`
	Hmac        string   `xml:"HMAC,attr"`
}
*/
var hmacSecretKey string = "UTv5N7OWd4wBRkrL4NbD"
var httpParallelism int = 100

func calcHmac(secret string, message []byte) string {

	key := []byte(secret)
	h := hmac.New(sha1.New, key)

	h.Write(message)
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}
func xmlTemplate(messageType string, hmac string, b64payload string) string {
	xml := "<pb type=\"%s\" HMAC=\"%s\">%s</pb>"
	return fmt.Sprintf(xml, messageType, hmac, b64payload)
}

var httpChannel chan string = make(chan string, httpParallelism)
var wg sync.WaitGroup

func doPosts(hostUrl string) {
	sem := make(chan int, httpParallelism)
	lru := tls.NewLRUClientSessionCache(1)

	tlsConfig := &tls.Config{InsecureSkipVerify: true,
		ClientSessionCache: lru,
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	//t := &http.Client{Transport: tr}
	client := &http.Client{Transport: tr}
	//hostUrl := "https://ec2-54-161-226-123.compute-1.amazonaws.com/api/datacollection/"

	for {
		sem <- 1
		go func() {

			payload := <-httpChannel

			req, _ := http.NewRequest("POST", hostUrl, bytes.NewBuffer([]byte(payload)))
			req.Header.Add("Content-Type", "text/xml")

			resp, err := client.Do(req)

			//fmt.Printf("Did Resume: %v\n\n", resp.TLS.DidResume)

			if err != nil {
				fmt.Println(err)
			} else {
				_, _ = ioutil.ReadAll(resp.Body)
				resp.Body.Close()

				fmt.Printf("%v,", resp.StatusCode)
			}
			<-sem
			wg.Done()
		}()

	}

}

// args
// hostUrl
func main() {
	//fmt.Println("Start")
	hostUrl := os.Args[1]

	go doPosts(hostUrl + "/api/datacollection/")

	database_file := "./zdbs/ziften_1_hour.zdb"
	now := time.Now()
	fmt.Printf("Now: %v\n", now)

	guid, _ := newUUID()
	siBytes := []byte{}

	db, err := sql.Open("sqlite3", database_file)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	msgTag := ""
	rows, err := db.Query("select msgtag,body from queue")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	var firstTimestamp int64 = -1
	var offset time.Duration = 0

	for rows.Next() {
		err = rows.Scan(&msgTag, &siBytes)
		if err != nil {
			log.Fatal(err)
		}

		if msgTag == "NetworkConnectSecondary" {
			//fmt.Printf("Skipping unsupported message type %s\n", msgTag)
			continue
		} else {
			//fmt.Printf("Adjusting message type: %s\n", msgTag)
		}
		msgType := proto.MessageType(msgTag).Elem()
		si := reflect.New(msgType).Interface()

		proto.Unmarshal(siBytes, si.(proto.Message))

		if firstTimestamp == -1 {
			firstTimestamp = *(reflect.ValueOf(si.(proto.Message)).Elem().FieldByName("TimeStamp").Interface().(*int64))
			//fmt.Printf("Setting first timestamp to: %v [[%v]]\n", firstTimestamp, WindowsTimeToGoTime(firstTimestamp))
			offset = now.Sub(WindowsTimeToGoTime(firstTimestamp))
			//fmt.Printf("Duration is %v\n", offset)
		}

		adjust(si.(proto.Message), offset)
		adjustGUID(msgTag, si.(proto.Message), guid)
		msgBytes, _ := proto.Marshal(si.(proto.Message))
		hmac := calcHmac(hmacSecretKey, msgBytes)
		msgEncoded := base64.StdEncoding.EncodeToString(msgBytes)
		//fmt.Printf("%s\n", xmlTemplate(msgTag, hmac, msgEncoded))

		payload := xmlTemplate(msgTag, hmac, msgEncoded)

		fmt.Printf("Sending %s\n", msgTag)
		wg.Add(1)
		httpChannel <- payload

	}

	err = rows.Err()
	if err != nil {
		log.Fatal(err)
	}
	wg.Wait()

}
