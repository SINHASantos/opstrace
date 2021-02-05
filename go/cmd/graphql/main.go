// Copyright 2021 Opstrace, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/opstrace/opstrace/go/pkg/graphql"
)

var (
	credentialClient graphql.CredentialAccess
	exporterClient graphql.ExporterAccess
)

func main() {
	var loglevel string
	flag.StringVar(&loglevel, "loglevel", "info", "error|info|debug")
	var listenAddress string
	flag.StringVar(&listenAddress, "listen", "", "")
	var graphqlURLstr string
	flag.StringVar(&graphqlURLstr, "graphql-url", "http://localhost:8080/v1/graphql", "")
	var tenantName string
	flag.StringVar(&tenantName, "tenantname", "", "")

	flag.Parse()

	level, lerr := log.ParseLevel(loglevel)
	if lerr != nil {
		log.Fatalf("bad --loglevel: %s", lerr)
	}
	log.SetLevel(level)

	if listenAddress == "" {
		log.Fatalf("missing required --listen")
	}
	log.Infof("listen address: %s", listenAddress)

	graphqlURL, uerr := url.Parse(graphqlURLstr)
	if uerr != nil {
		log.Fatalf("bad --graphql-url: %s", uerr)
	}
	if graphqlURL.String() == "" {
		log.Fatalf("missing required --graphql-url")
	}
	log.Infof("graphql URL: %v", graphqlURL)

	graphqlSecret := os.Getenv("HASURA_GRAPHQL_ADMIN_SECRET")
	if graphqlSecret == "" {
		log.Fatalf("missing required HASURA_GRAPHQL_ADMIN_SECRET")
	}

	if tenantName == "" {
		log.Fatalf("missing required --tenantname")
	}
	log.Infof("tenant name: %s", tenantName)

	credentialClient = graphql.NewCredentialAccess(tenantName, graphqlURL, graphqlSecret)
	exporterClient = graphql.NewExporterAccess(tenantName, graphqlURL, graphqlSecret)

	router := mux.NewRouter()
	router.Handle("/metrics", promhttp.Handler())

	// Specify exact paths, but manually allow with and without a trailing '/'

	credentials := router.PathPrefix("/api/v1/credentials").Subrouter()
	setupAPI(credentials, listCredentials, writeCredentials, getCredential, deleteCredential)

	exporters := router.PathPrefix("/api/v1/exporters").Subrouter()
	setupAPI(exporters, listExporters, writeExporters, getExporter, deleteExporter)

	log.Fatalf("terminated: %v", http.ListenAndServe(listenAddress, router))
}

/// setupAPI configures GET/POST/DELETE endpoints for the provided handler callbacks.
/// The paths are configured to be exact, with optional trailing slashes.
func setupAPI(
	router *mux.Router,
	listFunc func(http.ResponseWriter, *http.Request),
	writeFunc func(http.ResponseWriter, *http.Request),
	getFunc func(http.ResponseWriter, *http.Request),
	deleteFunc func(http.ResponseWriter, *http.Request),
) {
	router.HandleFunc("", listFunc).Methods("GET")
	router.HandleFunc("/", listFunc).Methods("GET")
	router.HandleFunc("", writeFunc).Methods("POST")
	router.HandleFunc("/", writeFunc).Methods("POST")
	router.HandleFunc("/{name}", getFunc).Methods("GET")
	router.HandleFunc("/{name}/", getFunc).Methods("GET")
	router.HandleFunc("/{name}", deleteFunc).Methods("DELETE")
	router.HandleFunc("/{name}/", deleteFunc).Methods("DELETE")
}

/// Information about a credential. Custom type which omits the tenant field.
/// This also given some extra protection that the value isn't disclosed, even if was mistakenly added to the underlying graphql interface.
type CredentialInfo struct {
	Name string `yaml:"name"`
	Type string `yaml:"type,omitempty"`
	CreatedAt string `yaml:"created_at,omitempty"`
	UpdatedAt string `yaml:"updated_at,omitempty"`
}

func listCredentials(w http.ResponseWriter, r *http.Request) {
	resp, err := credentialClient.List()
	if err != nil {
		log.Warnf("Listing credentials failed: %s", err)
		http.Error(w, fmt.Sprintf("Listing credentials failed: %s", err), http.StatusInternalServerError)
		return
	}

	log.Debugf("Listing %d credentials", len(resp.Credential))

	encoder := yaml.NewEncoder(w)
	for _, credential := range resp.Credential {
		encoder.Encode(CredentialInfo{
			Name: credential.Name,
			Type: credential.Type,
			CreatedAt: credential.CreatedAt,
			UpdatedAt: credential.UpdatedAt,
		})
	}
}

/// Full credential entry (with secret value) received from a POST request.
type Credential struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
	Value string `yaml:"value"` // TODO interface{} instead of string?
}

func writeCredentials(w http.ResponseWriter, r *http.Request) {
	decoder := yaml.NewDecoder(r.Body)
	// Return error for unrecognized or duplicate fields in the input
	decoder.SetStrict(true)

	// Collect list of existing names so that we can decide between insert vs update
	existingTypes := make(map[string]string)
	resp, err := credentialClient.List()
	if err != nil {
		log.Warnf("Listing credentials failed: %s", err)
		http.Error(w, fmt.Sprintf("Listing credentials failed: %s", err), http.StatusInternalServerError)
		return
	}
	for _, credential := range resp.Credential {
		existingTypes[credential.Name] = credential.Type
	}

	now := nowTimestamp()

	var inserts []graphql.CredentialInsertInput
	var updates []graphql.UpdateCredentialVariables
	for {
		var yamlCredential Credential
		err := decoder.Decode(&yamlCredential)
		if err != nil {
			if err != io.EOF {
				log.Debugf("Decoding exporter input at index=%d failed: %s", len(inserts)+len(updates), err)
				http.Error(w, fmt.Sprintf("Decoding credential input at index=%d failed: %s", len(inserts)+len(updates), err), http.StatusBadRequest)
				return
			}
			break
		}
		name := graphql.String(yamlCredential.Name)
		value := graphql.Bytea(yamlCredential.Value) // TODO validate format of value based on the type
		if existingType, ok := existingTypes[yamlCredential.Name]; ok {
			// Explicitly check and complain if the user tries to change the credential type
			if yamlCredential.Type != "" && existingType != yamlCredential.Type {
				log.Debugf("Invalid credential '%s' type change", yamlCredential.Name)
				http.Error(w, fmt.Sprintf("Credential '%s' type cannot be updated (current=%s, updated=%s)", yamlCredential.Name, existingType, yamlCredential.Type), http.StatusBadRequest)
				return
			}
			// TODO check for no-op updates and skip them (and avoid unnecessary changes to UpdatedAt)
			updates = append(updates, graphql.UpdateCredentialVariables{
				Name: name,
				Value: value,
				UpdatedAt: now,
			})
		} else {
			credType := graphql.String(yamlCredential.Type)
			inserts = append(inserts, graphql.CredentialInsertInput{
				Name: &name,
				Type: &credType,
				Value: &value,
				CreatedAt: &now,
				UpdatedAt: &now,
			})
		}
	}

	if len(inserts) + len(updates) == 0 {
		log.Debugf("Writing credentials: No data provided")
		http.Error(w, fmt.Sprintf("Missing credential YAML data in request body"), http.StatusBadRequest)
		return
	}

	log.Debugf("Writing credentials: %d insert, %d update", len(inserts), len(updates))

	if len(inserts) != 0 {
		err := credentialClient.Insert(inserts)
		if err != nil {
			log.Warnf("Insert: %d credentials failed: %s", len(inserts), err)
			http.Error(w, fmt.Sprintf("Creating %d credentials failed: %s", len(inserts), err), http.StatusInternalServerError)
			return
		}
	}
	if len(updates) != 0 {
		for _, update := range updates {
			err := credentialClient.Update(update)
			if err != nil {
				log.Warnf("Update: Credential %s failed: %s", update.Name, err)
				http.Error(w, fmt.Sprintf("Updating credential %s failed: %s", update.Name, err), http.StatusInternalServerError)
				return
			}
		}
	}
}

func getCredential(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
    log.Debugf("Getting credential: %s", name)

	resp, err := credentialClient.Get(name)
	if err != nil {
		log.Warnf("Get: Credential %s failed: %s", name, err)
		http.Error(w, fmt.Sprintf("Getting credential failed: %s", err), http.StatusInternalServerError)
		return
	}
	if resp == nil {
		log.Debugf("Get: Credential %s not found", name)
		http.Error(w, fmt.Sprintf("Credential not found: %s", name), http.StatusNotFound)
		return
	}

	encoder := yaml.NewEncoder(w)
	encoder.Encode(CredentialInfo{
		Name: resp.CredentialByPk.Name,
		Type: resp.CredentialByPk.Type,
		CreatedAt: resp.CredentialByPk.CreatedAt,
		UpdatedAt: resp.CredentialByPk.UpdatedAt,
	})
}

func deleteCredential(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
    log.Debugf("Deleting credential: %s", name)

	resp, err := credentialClient.Delete(name)
	if err != nil {
		log.Warnf("Delete: Credential %s failed: %s", name, err)
		http.Error(w, fmt.Sprintf("Deleting credential failed: %s", err), http.StatusInternalServerError)
		return
	}
	if resp == nil {
		log.Debugf("Delete: Credential %s not found", name)
		http.Error(w, fmt.Sprintf("Credential not found: %s", name), http.StatusNotFound)
		return
	}

	encoder := yaml.NewEncoder(w)
	encoder.Encode(CredentialInfo{ Name: resp.DeleteCredentialByPk.Name })
}

/// Information about an exporter. Custom type which omits the tenant field.
type ExporterInfo struct {
	Name string `yaml:"name"`
	Type string `yaml:"type,omitempty"`
	Credential string `yaml:"credential,omitempty"`
	Config string `yaml:"config,omitempty"`
	CreatedAt string `yaml:"created_at,omitempty"`
	UpdatedAt string `yaml:"updated_at,omitempty"`
}

func listExporters(w http.ResponseWriter, r *http.Request) {
	resp, err := exporterClient.List()
	if err != nil {
		log.Warnf("Listing exporters failed: %s", err)
		http.Error(w, fmt.Sprintf("Listing exporters failed: %s", err), http.StatusInternalServerError)
		return
	}

	log.Debugf("Listing %d exporters", len(resp.Exporter))

	encoder := yaml.NewEncoder(w)
	for _, exporter := range resp.Exporter {
		encoder.Encode(ExporterInfo{
			Name: exporter.Name,
			Type: exporter.Type,
			Credential: exporter.Credential,
			Config: exporter.Config,
			CreatedAt: exporter.CreatedAt,
			UpdatedAt: exporter.UpdatedAt,
		})
	}
}

/// Exporter entry received from a POST request.
type Exporter struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
	Credential string `yaml:"credential,omitempty"`
	Config string `yaml:"config"` // TODO interface{} type instead of string?
}

func writeExporters(w http.ResponseWriter, r *http.Request) {
	decoder := yaml.NewDecoder(r.Body)
	// Return error for unrecognized or duplicate fields in the input
	decoder.SetStrict(true)

	// Collect list of existing names so that we can decide between insert vs update
	existingTypes := make(map[string]string)
	resp, err := exporterClient.List()
	if err != nil {
		log.Warnf("Listing exporters failed: %s", err)
		http.Error(w, fmt.Sprintf("Listing exporters failed: %s", err), http.StatusInternalServerError)
		return
	}
	for _, exporter := range resp.Exporter {
		existingTypes[exporter.Name] = exporter.Type
	}

	now := nowTimestamp()

	var inserts []graphql.ExporterInsertInput
	var updates []graphql.UpdateExporterVariables
	for {
		var yamlExporter Exporter
		err := decoder.Decode(&yamlExporter)
		if err != nil {
			if err != io.EOF {
				log.Debugf("Decoding exporter input at index=%d failed: %s", len(inserts)+len(updates), err)
				http.Error(w, fmt.Sprintf("Decoding exporter input at index=%d failed: %s", len(inserts)+len(updates), err), http.StatusBadRequest)
				return
			}
			break
		}
		name := graphql.String(yamlExporter.Name)
		var credential *graphql.String
		if yamlExporter.Credential == "" {
			credential = nil
		} else {
			// TODO could validate that the referenced credential has the correct type for this exporter
			// for example, require that cloudwatch exporters are configured with aws-key credentials
			gcredential := graphql.String(yamlExporter.Credential)
			credential = &gcredential
		}
		config := graphql.Json(yamlExporter.Config) // TODO convert yaml to json?
		if existingType, ok := existingTypes[yamlExporter.Name]; ok {
			// Explicitly check and complain if the user tries to change the exporter type
			if yamlExporter.Type != "" && existingType != yamlExporter.Type {
				log.Debugf("Invalid exporter '%s' type change", yamlExporter.Name)
				http.Error(w, fmt.Sprintf("Exporter '%s' type cannot be updated (current=%s, updated=%s)", yamlExporter.Name, existingType, yamlExporter.Type), http.StatusBadRequest)
				return
			}
			// TODO check for no-op updates and skip them (and avoid unnecessary changes to UpdatedAt)
			updates = append(updates, graphql.UpdateExporterVariables{
				Name: name,
				Credential: credential,
				Config: config,
				UpdatedAt: now,
			})
		} else {
			expType := graphql.String(yamlExporter.Type)
			inserts = append(inserts, graphql.ExporterInsertInput{
				Name: &name,
				Type: &expType,
				Credential: credential,
				Config: &config,
				CreatedAt: &now,
				UpdatedAt: &now,
			})
		}
	}

	if len(inserts) + len(updates) == 0 {
		log.Debugf("Writing exporters: No data provided")
		http.Error(w, fmt.Sprintf("Missing exporter YAML data in request body"), http.StatusBadRequest)
		return
	}

	log.Debugf("Writing exporters: %d insert, %d update", len(inserts), len(updates))

	if len(inserts) != 0 {
		err := exporterClient.Insert(inserts)
		if err != nil {
			log.Warnf("Insert: %d credentials failed: %s", len(inserts), err)
			http.Error(w, fmt.Sprintf("Creating %d exporters failed: %s", len(inserts), err), http.StatusInternalServerError)
			return
		}
	}
	if len(updates) != 0 {
		for _, update := range updates {
			err := exporterClient.Update(update)
			if err != nil {
				log.Warnf("Update: Credential %s failed: %s", update.Name, err)
				http.Error(w, fmt.Sprintf("Updating exporter %s failed: %s", update.Name, err), http.StatusInternalServerError)
				return
			}
		}
	}
}

func getExporter(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
    log.Debugf("Getting exporter: %s", name)

	resp, err := exporterClient.Get(name)
	if err != nil {
		log.Warnf("Get: Exporter %s failed: %s", name, err)
		http.Error(w, fmt.Sprintf("Getting exporter failed: %s", err), http.StatusInternalServerError)
		return
	}
	if resp == nil {
		log.Debugf("Get: Exporter %s not found", name)
		http.Error(w, fmt.Sprintf("Exporter not found: %s", name), http.StatusNotFound)
		return
	}

	encoder := yaml.NewEncoder(w)
	encoder.Encode(ExporterInfo{
		Name: resp.ExporterByPk.Name,
		Type: resp.ExporterByPk.Type,
		Credential: resp.ExporterByPk.Credential,
		Config: resp.ExporterByPk.Config,
		CreatedAt: resp.ExporterByPk.CreatedAt,
		UpdatedAt: resp.ExporterByPk.UpdatedAt,
	})
}

func deleteExporter(w http.ResponseWriter, r *http.Request) {
	name := mux.Vars(r)["name"]
    log.Debugf("Deleting exporter: %s", name)

	resp, err := exporterClient.Delete(name)
	if err != nil {
		log.Warnf("Delete: Exporter %s failed: %s", name, err)
		http.Error(w, fmt.Sprintf("Deleting exporter failed: %s", err), http.StatusInternalServerError)
		return
	}
	if resp == nil {
		log.Debugf("Delete: Exporter %s not found", name)
		http.Error(w, fmt.Sprintf("Exporter not found: %s", name), http.StatusNotFound)
		return
	}

	encoder := yaml.NewEncoder(w)
	encoder.Encode(ExporterInfo{ Name: resp.DeleteExporterByPk.Name })
}

/// Returns a string representation of the current time in UTC, suitable for passing to Hasura as a timestamptz
/// See also https://hasura.io/blog/postgres-date-time-data-types-on-graphql-fd926e86ee87/
func nowTimestamp() graphql.Timestamptz {
	// TODO see if RFC3339 is accepted
	return graphql.Timestamptz(time.Now().Format(time.RFC3339))
}
