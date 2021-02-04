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
	"net/http"
	"net/url"
	"os"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v2"

	"github.com/opstrace/opstrace/go/pkg/graphql"
)

var (
	loglevel      string
	listenAddress string
	graphqlURL    string
	graphqlSecret string
	tenantName    graphql.String

	client *graphql.Client
)

func main() {
	flag.StringVar(&loglevel, "loglevel", "info", "error|info|debug")
	flag.StringVar(&listenAddress, "listen", "", "")
	flag.StringVar(&graphqlURL, "graphql-url", "http://localhost:8080/v1/graphql", "")
	var rawTenantName string
	flag.StringVar(&rawTenantName, "tenantname", "", "")

	flag.Parse()

	level, lerr := log.ParseLevel(loglevel)
	if lerr != nil {
		log.Fatalf("bad log level: %s", lerr)
	}
	log.SetLevel(level)

	if listenAddress == "" {
		log.Fatalf("missing required --listen")
	}
	log.Infof("listen address: %s", listenAddress)

	graphqlurl, uerr := url.Parse(graphqlURL)
	if uerr != nil {
		log.Fatalf("bad graphql-url: %s", uerr)
	}
	if graphqlurl.String() == "" {
		log.Fatalf("missing required --graphql-url")
	}
	log.Infof("graphql URL: %s", graphqlurl)

	graphqlSecret = os.Getenv("HASURA_GRAPHQL_ADMIN_SECRET")
	if graphqlSecret == "" {
		log.Info("graphql secret: NONE (missing HASURA_GRAPHQL_ADMIN_SECRET)")
	} else {
		log.Info("graphql secret: configured")
	}

	if rawTenantName == "" {
		log.Fatalf("missing required --tenantname")
	}
	log.Infof("tenant name: %s", rawTenantName)
	tenantName = graphql.String(rawTenantName)

	client = graphql.NewClient(graphqlurl.String())

	router := mux.NewRouter()
	router.Handle("/metrics", promhttp.Handler())

	// Specify exact paths, but manually allow with and without a trailing '/'

	credentials := router.PathPrefix("/api/v1/credentials").Subrouter()
	setupAPI(credentials, listCredentials, writeCredentials, getCredential, deleteCredential)

	exporters := router.PathPrefix("/api/v1/exporters").Subrouter()
	setupAPI(exporters, listExporters, writeExporters, getExporter, deleteExporter)

	log.Fatalf("terminated: %s", http.ListenAndServe(listenAddress, router))
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
	Name string `json:"name"`
	Type string `json:"type"`
	CreatedAt string `json:"createdat"` // TODO this doesn't seem to be populated? problem with write call?
}

func listCredentials(w http.ResponseWriter, r *http.Request) {
	req, err := graphql.NewGetCredentialsRequest(client.Url, &graphql.GetCredentialsVariables{ Tenant: tenantName })
	if err != nil {
		log.Fatalf("Invalid list credentials request: %s", err)
	}
	addSecret(req.Request)

	resp, err := req.Execute(client.Client)
	if err != nil {
		log.Fatalf("List credentials failed: %s", err) // TODO pass through error to response
	}
	log.Infof("list credentials: %s", resp)

	encoder := yaml.NewEncoder(w)
	for _, credential := range resp.Credential {
		encoder.Encode(CredentialInfo{ Name: credential.Name, Type: credential.Type, CreatedAt: credential.CreatedAt })
	}
}

/// Full credential entry (with secret value) received from a POST request.
type Credential struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Value string `json:"value"`
}

func writeCredentials(w http.ResponseWriter, r *http.Request) {
	decoder := yaml.NewDecoder(r.Body)
	decoder.SetStrict(true) // TODO(nickbp) figure out what strict does

	var credentials []graphql.CredentialInsertInput
	for {
		var rawCredential Credential
		err := decoder.Decode(&rawCredential)
		if err != nil { // TODO(nickbp) figure out the difference between bad data (abort entire request) vs end of data (break loop)
			break
		}
		name := graphql.String(rawCredential.Name)
		cred_type := graphql.String(rawCredential.Type)
		value := graphql.Bytea(rawCredential.Value)
		credentials = append(credentials, graphql.CredentialInsertInput{
			Tenant: &tenantName,
			Name: &name,
			Type: &cred_type,
			Value: &value,
		})
	}

	log.Info("write %d credentials", len(credentials))

	req, err := graphql.NewCreateCredentialsRequest(client.Url, &graphql.CreateCredentialsVariables{ Credentials: &credentials })
	if err != nil {
		log.Fatalf("Invalid create credentials request: %s", err)
	}
	addSecret(req.Request)

	_, err = req.Execute(client.Client)
	if err != nil {
		log.Fatalf("Failed to create credentials: %s", err) // TODO pass through error to response
	}
}

func getCredential(w http.ResponseWriter, r *http.Request) {
	name := graphql.String(mux.Vars(r)["name"])

	req, err := graphql.NewGetCredentialRequest(client.Url, &graphql.GetCredentialVariables{ Tenant: tenantName, Name: name })
	if err != nil {
		log.Fatalf("Invalid get credential request: %s", err)
	}
	addSecret(req.Request)

	resp, err := req.Execute(client.Client)
	if err != nil {
		log.Fatalf("Get credential failed: %s", err) // TODO pass through error to response
	}
	if resp.CredentialByPk.Name == "" {
		// TODO return 404
	}
	log.Infof("get credential name=%s: %s", name, resp)

	encoder := yaml.NewEncoder(w)
	encoder.Encode(CredentialInfo{ Name: resp.CredentialByPk.Name, Type: resp.CredentialByPk.Type, CreatedAt: resp.CredentialByPk.CreatedAt })
}

func deleteCredential(w http.ResponseWriter, r *http.Request) {
	name := graphql.String(mux.Vars(r)["name"])

	req, err := graphql.NewDeleteCredentialRequest(client.Url, &graphql.DeleteCredentialVariables{ Tenant: tenantName, Name: name })
	if err != nil {
		log.Fatalf("Invalid delete credential request: %s", err)
	}
	addSecret(req.Request)

	resp, err := req.Execute(client.Client)
	if err != nil {
		log.Fatalf("Delete credential failed: %s", err) // TODO pass through error to response
	}
	if resp.DeleteCredentialByPk.Name == "" {
		// TODO return 404
	}
	log.Infof("delete credential name=%s: %s", name, resp)

	encoder := yaml.NewEncoder(w)
	encoder.Encode(resp.DeleteCredentialByPk.Name)
}

/// Information about an exporter. Custom type which omits the tenant field.
type ExporterInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Credential string `json:"credential,omitempty"`
	Config string `json:"config"`
	CreatedAt string `json:"createdat"` // TODO this doesn't seem to be populated? problem with write call?
}

func listExporters(w http.ResponseWriter, r *http.Request) {
	req, err := graphql.NewGetExportersRequest(client.Url, &graphql.GetExportersVariables{ Tenant: tenantName })
	if err != nil {
		log.Fatalf("Invalid list exporters request: %s", err)
	}
	addSecret(req.Request)

	resp, err := req.Execute(client.Client)
	if err != nil {
		log.Fatalf("List exporters failed: %s", err) // TODO pass through error to response
	}
	log.Infof("list exporters: %s", resp)

	encoder := yaml.NewEncoder(w)
	for _, exporter := range resp.Exporter {
		encoder.Encode(ExporterInfo{
			Name: exporter.Name,
			Type: exporter.Type,
			Credential: exporter.Credential,
			Config: exporter.Config,
			CreatedAt: exporter.CreatedAt,
		})
	}
}

/// Exporter entry received from a POST request.
type Exporter struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Credential string `json:"credential,omitempty"`
	Config string `json:"config"`
}

func writeExporters(w http.ResponseWriter, r *http.Request) {
	decoder := yaml.NewDecoder(r.Body)
	decoder.SetStrict(true) // TODO(nickbp) figure out what strict does

	var exporters []graphql.ExporterInsertInput
	for {
		var rawExporter Exporter
		err := decoder.Decode(&rawExporter)
		if err != nil { // TODO(nickbp) figure out the difference between bad data (abort entire request) vs end of data (break loop)
			break
		}
		name := graphql.String(rawExporter.Name)
		exp_type := graphql.String(rawExporter.Type)
		credential := graphql.String(rawExporter.Credential)
		config := graphql.Json(rawExporter.Config)
		exporters = append(exporters, graphql.ExporterInsertInput{
			Tenant: &tenantName,
			Name: &name,
			Type: &exp_type,
			Credential: &credential,
			Config: &config,
		})
	}

	log.Info("write %d exporters", len(exporters))

	req, err := graphql.NewCreateExportersRequest(client.Url, &graphql.CreateExportersVariables{ Exporters: &exporters })
	if err != nil {
		log.Fatalf("Invalid create exporters request: %s", err)
	}
	addSecret(req.Request)

	_, err = req.Execute(client.Client)
	if err != nil {
		log.Fatalf("Failed to create exporters: %s", err) // TODO pass through error to response
	}
}

func getExporter(w http.ResponseWriter, r *http.Request) {
	name := graphql.String(mux.Vars(r)["name"])

	req, err := graphql.NewGetExporterRequest(client.Url, &graphql.GetExporterVariables{ Tenant: tenantName, Name: name })
	if err != nil {
		log.Fatalf("Invalid get exporter request: %s", err)
	}
	addSecret(req.Request)

	resp, err := req.Execute(client.Client)
	if err != nil {
		log.Fatalf("Get exporter failed: %s", err) // TODO pass through error to response
	}
	if resp.ExporterByPk.Name == "" {
		// TODO return 404
	}
	log.Infof("get exporter name=%s: %s", name, resp)

	encoder := yaml.NewEncoder(w)
	encoder.Encode(ExporterInfo{
		Name: resp.ExporterByPk.Name,
		Type: resp.ExporterByPk.Type,
		Credential: resp.ExporterByPk.Credential,
		Config: resp.ExporterByPk.Config,
		CreatedAt: resp.ExporterByPk.CreatedAt,
	})
}

func deleteExporter(w http.ResponseWriter, r *http.Request) {
	name := graphql.String(mux.Vars(r)["name"])

	req, err := graphql.NewDeleteExporterRequest(client.Url, &graphql.DeleteExporterVariables{ Tenant: tenantName, Name: name })
	if err != nil {
		log.Fatalf("Invalid delete exporter request: %s", err)
	}
	addSecret(req.Request)

	resp, err := req.Execute(client.Client)
	if err != nil {
		log.Fatalf("Delete exporter failed: %s", err) // TODO pass through error to response
	}
	if resp.DeleteExporterByPk.Name == "" {
		// TODO return 404
	}
	log.Infof("delete exporter name=%s: %s", name, resp)

	encoder := yaml.NewEncoder(w)
	encoder.Encode(resp.DeleteExporterByPk.Name)
}

/// addSecret adds the required HTTP header for talking to the Hasura graphql server
func addSecret(req *http.Request) {
	if graphqlSecret != "" {
		req.Header.Add("x-hasura-admin-secret", graphqlSecret)
	}
}
