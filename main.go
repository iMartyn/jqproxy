package main

import (
	"github.com/ant0ine/go-json-rest/rest"
	"github.com/threatgrid/jqpipe-go"
	"github.com/spf13/viper"
	"github.com/fsnotify/fsnotify"
	"log"
	"net/http"
	"strings"
	"io/ioutil"
)

type definition struct {
	data string
	operation string
}

var definitions map[string]definition

func main() {
	viper.SetConfigName("jqproxy")
	viper.AddConfigPath("/etc/jqproxy")
	viper.AddConfigPath("$HOME/.jqproxy")
	viper.AddConfigPath(".")
	viper.ReadInConfig()
	viper.WatchConfig()
	viper.OnConfigChange(func(e fsnotify.Event) {
		log.Println("Config file changed:", e.Name)
		viper.ReadInConfig()
	})
	api := rest.NewApi()
	api.Use(rest.DefaultDevStack...)
	router, err := rest.MakeRouter(
		rest.Get("/#definition", func(w rest.ResponseWriter, req *rest.Request) {
			if viper.IsSet(req.PathParam("definition")) || req.PathParam("definition") == "jqproxy" {
				thisdefinition := req.PathParam("definition")
				data := "";
				if viper.IsSet(thisdefinition+".data") {
					data = viper.GetString(thisdefinition+".data")
				} else if viper.IsSet(thisdefinition+".url") {
					resp, err := http.Get(viper.GetString(thisdefinition+".url"))
					if err != nil {
						rest.Error(w, "Error fetching upstream ("+viper.GetString(thisdefinition+".url")+") "+err.Error(), http.StatusInternalServerError)
						return
					}
					defer resp.Body.Close()
					bytes, err := ioutil.ReadAll(resp.Body)
					if err != nil {
						rest.Error(w, "Error fetching upstream ("+viper.GetString(thisdefinition+".url")+") "+err.Error(), http.StatusInternalServerError)
						return
					}
					data = string(bytes)
				}
				munged, err := jq.Eval(data,viper.GetString(thisdefinition+".operation"))
				if err != nil {
					rest.Error(w, "Error: jq operation error : " +err.Error(), http.StatusInternalServerError)
					return
				}
				if viper.IsSet(thisdefinition+".output") && viper.GetString(thisdefinition+".output") != "json" {
					w.Header().Set("Content-Type", "text/plain")
					for i := range munged {
						if viper.GetString(thisdefinition+".output") == "strings" {
							trimmed := strings.TrimPrefix(string(munged[i]), "\"")
							fullytrimmed := strings.TrimSuffix(trimmed, "\"")
							w.(http.ResponseWriter).Write([]byte(fullytrimmed+"\n"))
						}
					}
				} else {
					for i := range munged {
						w.WriteJson(munged[i])
					}
				}
			} else {
				rest.Error(w, "No definition of "+req.PathParam("definition")+" found.", http.StatusNotFound)
			}
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	api.SetApp(router)
	log.Fatal(http.ListenAndServe(":8080", api.MakeHandler()))
}
