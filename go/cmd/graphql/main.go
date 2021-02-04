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

	log "github.com/sirupsen/logrus"

	"github.com/opstrace/opstrace/go/pkg/graphql"
)

var (
	loglevel      string
	graphqlURL    string
	graphqlSecret string
)

func main() {
	flag.StringVar(&loglevel, "loglevel", "info", "error|info|debug")
	flag.StringVar(&graphqlURL, "graphql-url", "http://localhost:8080/v1/graphql", "")
	flag.StringVar(&graphqlSecret, "graphql-secret", "", "")

	flag.Parse()

	level, lerr := log.ParseLevel(loglevel)
	if lerr != nil {
		log.Fatalf("bad log level: %s", lerr)
	}
	log.SetLevel(level)

	graphqlurl, uerr := url.Parse(graphqlURL)
	if uerr != nil {
		log.Fatalf("bad graphql-url: %s", uerr)
	}
	if graphqlurl.String() == "" {
		log.Fatalf("missing required --graphql-url")
	}
	log.Infof("graphql URL: %s", graphqlurl)

	if graphqlSecret == "" {
		// Try env
		graphqlSecret = os.Getenv("HASURA_GRAPHQL_ADMIN_SECRET")
		if graphqlSecret == "" {
			log.Info("graphql secret: NONE (use --graphql-secret or HASURA_GRAPHQL_ADMIN_SECRET)")
		} else {
			log.Info("graphql secret: configured:ENV")
		}
	} else {
		log.Info("graphql secret: configured:FLAG")
	}

	// TODO implement local HTTP endpoints accepting yaml payloads, extract these from that
	tenant := "tenant-foo"
	credential_name := "cred-foo"
	credential_type := "aws-key"
	credential_value := "top secret"
	exporter_name := "exporter-foo"
	exporter_type := "cloudwatch"
	exporter_config := "{ \"json\": \"payload\" }"

	client := graphql.NewClient(graphqlurl.String())

	// TODO remove tenant add once done testing
	tenants, err := getTenantNames(client)
	if err != nil {
		log.Fatalf("Tenant get err: %s", err)
	} else {
		log.Infof("Tenant list response: %s", tenants)
	}
	var tenant_exists = false
	for _, t := range tenants {
		if tenant == t {
			tenant_exists = true
			break
		}
	}
	if !tenant_exists {
		tresp, err := createTenant(client, tenant, "testing")
		if err != nil {
			log.Fatalf("Tenant create err: %s", err)
		} else {
			log.Infof("Tenant create response: %s", tresp)
		}
	}

	// Write the credential
	cresp, err := createCredential(client, credential_name, tenant, credential_type, credential_value)
	if err != nil {
		log.Fatalf("Credential create err: %s", err)
	} else {
		log.Infof("Credential create response: %s", cresp)
	}

	// Write the exporter using the credential
	eresp, err := createExporter(client, exporter_name, tenant, exporter_type, &credential_name, exporter_config)
	if err != nil {
		log.Fatalf("Exporter create err: %s", err)
	} else {
		log.Infof("Exporter create response: %s", eresp)
	}
}

func createCredential(client *graphql.Client, name string, tenant string, credential_type string, value string) (*graphql.CreateCredentialsResponse, error) {
	n := graphql.String(name)
	t := graphql.String(tenant)
	ctype := graphql.String(credential_type)
	v := graphql.Bytea(value)
	credential := graphql.CredentialInsertInput{ Name: &n, Tenant: &t, Type: &ctype, Value: &v }
	req, err := graphql.NewCreateCredentialsRequest(client.Url, &graphql.CreateCredentialsVariables{ Credentials: &[]graphql.CredentialInsertInput{ credential } })
	if err != nil {
		log.Fatalf("Invalid create credentials request: %s", err)
	}
	addSecret(req.Request)

	log.Infof("Creating credential: name=%s tenant=%s type=%s", name, tenant, credential_type)
	return req.Execute(client.Client)
}

func createExporter(client *graphql.Client, name string, tenant string, exporter_type string, credential *string, config string) (*graphql.CreateExportersResponse, error) {
	n := graphql.String(name)
	t := graphql.String(tenant)
	etype := graphql.String(exporter_type)
	var credp *graphql.String
	if credential != nil {
		c := graphql.String(*credential)
		credp = &c
	} else {
		credp = nil
	}
	conf := graphql.Json(config)
	exporter := graphql.ExporterInsertInput{ Name: &n, Tenant: &t, Type: &etype, Credential: credp, Config: &conf }
	req, err := graphql.NewCreateExportersRequest(client.Url, &graphql.CreateExportersVariables{ Exporters: &[]graphql.ExporterInsertInput{ exporter } })
	if err != nil {
		log.Fatalf("Invalid create exporters request: %s", err)
	}
	addSecret(req.Request)

	log.Infof("Creating exporter: name=%s tenant=%s type=%s", name, tenant, exporter_type)
	return req.Execute(client.Client)
}

func getTenantNames(client *graphql.Client) ([]string, error) {
	req, err := graphql.NewGetTenantsRequest(client.Url)
	if err != nil {
		log.Fatalf("Invalid get tenants request: %s", err)
	}
	addSecret(req.Request)

	log.Infof("Getting tenants")
	resp, err := req.Execute(client.Client)
	if err != nil {
		return nil, err
	}

	var names []string
	for _, tenant := range resp.Tenant {
		names = append(names, tenant.Name)
	}
	return names, nil
}

func createTenant(client *graphql.Client, name string, tenant_type string) (*graphql.CreateTenantsResponse, error) {
	n := graphql.String(name)
	t := graphql.String(tenant_type)
	tenant := graphql.TenantInsertInput{ Name: &n, Type: &t }
	req, err := graphql.NewCreateTenantsRequest(client.Url, &graphql.CreateTenantsVariables{ Tenants: &[]graphql.TenantInsertInput{ tenant } })
	if err != nil {
		log.Fatalf("Invalid create tenants request: %s", err)
	}
	addSecret(req.Request)

	log.Infof("Creating tenants: name=%s type=%s", name, tenant_type)
	return req.Execute(client.Client)
}

func addSecret(req *http.Request) {
	if graphqlSecret != "" {
		req.Header.Add("x-hasura-admin-secret", graphqlSecret)
	}
}
