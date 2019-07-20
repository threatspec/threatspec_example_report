// From http://golang.org/doc/articles/wiki/final.go?m=text
// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

/* 
@threat arbitrary file writes (#file_writes):
  description: An attacker can make arbitrary changes to files on the file system, for example overwriting /etc/hosts.
  impact: high

@threat Cross-site Scripting (#xss):
  description: |
    Cross-site scripting (XSS) is a type of computer security vulnerability typically found in web applications. XSS enables 
    attackers to inject client-side scripts into web pages viewed by other users. A cross-site scripting vulnerability may be 
    used by attackers to bypass access controls such as the same-origin policy. Cross-site scripting carried out on websites 
    accounted for roughly 84% of all security vulnerabilities documented by Symantec as of 2007. (Wikipedia)

@control Web Application Firewall (#waf):
  description: Monitors and blocks malicious web traffic.
*/

package main

import (
    "flag"
    "html/template"
    "io/ioutil"
    "log"
    "net"
    "net/http"
    "regexp"
)

var (
    addr = flag.Bool("addr", false, "find open address and print to final-port.txt")
)

type Page struct {
    Title string
    Body  []byte
}

// @accepts #file_writes to WebApp:FileSystem with filename restrictions that limit the possible filenames written to by an attacker
/*
@mitigates WebApp:FileSystem against unauthorised access with #file_perms:
  description: Access is limited strictly to the owner of the file
*/
func (p *Page) save() error {
    filename := p.Title + ".txt"
    return ioutil.WriteFile(filename, p.Body, 0600)
}

// @accepts arbitrary file reads to WebApp:FileSystem with filename restrictions
func loadPage(title string) (*Page, error) {
    filename := title + ".txt"
    body, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    return &Page{Title: title, Body: body}, nil
}

func viewHandler(w http.ResponseWriter, r *http.Request, title string) {
    p, err := loadPage(title)
    if err != nil {
        http.Redirect(w, r, "/edit/"+title, http.StatusFound)
        return
    }
    renderTemplate(w, "view", p)
}

// @exposes WebApp:App to #xss with insufficient input validation
func editHandler(w http.ResponseWriter, r *http.Request, title string) {
    p, err := loadPage(title)
    if err != nil {
        p = &Page{Title: title}
    }
    renderTemplate(w, "edit", p)
}

// @exposes WebApp:App to content injection with insufficient input validation
func saveHandler(w http.ResponseWriter, r *http.Request, title string) {
    body := r.FormValue("body")
    p := &Page{Title: title, Body: []byte(body)}
    err := p.save()
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
        return
    }
    http.Redirect(w, r, "/view/"+title, http.StatusFound)
}

var templates = template.Must(template.ParseFiles("edit.html", "view.html"))

func renderTemplate(w http.ResponseWriter, tmpl string, p *Page) {
    err := templates.ExecuteTemplate(w, tmpl+".html", p)
    if err != nil {
        http.Error(w, err.Error(), http.StatusInternalServerError)
    }
}

var validPath = regexp.MustCompile("^/(edit|save|view)/([a-zA-Z0-9]+)$")

// @mitigates WebApp:Web against resource access abuse with basic input validation
func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        m := validPath.FindStringSubmatch(r.URL.Path)
        if m == nil {
            http.NotFound(w, r)
            return
        }
        fn(w, r, m[2])
    }
}

// @mitigates WebApp:Web against privilege escalation with non-privileged port
// @transfers @cwe_319_cleartext_transmission from WebApp:Web to User:Browser with non-sensitive information
func main() {
    flag.Parse()
    http.HandleFunc("/view/", makeHandler(viewHandler))
    http.HandleFunc("/edit/", makeHandler(editHandler))
    http.HandleFunc("/save/", makeHandler(saveHandler))

    if *addr {
        l, err := net.Listen("tcp", "127.0.0.1:0")
        if err != nil {
            log.Fatal(err)
        }
        err = ioutil.WriteFile("final-port.txt", []byte(l.Addr().String()), 0644) // @review WebApp:Web Is this a security feature?
        if err != nil {
            log.Fatal(err)
        }
        s := &http.Server{}
        s.Serve(l)
        return
    }

    http.ListenAndServe(":8080", nil) // @connects User:Browser to WebApp:Web with HTTP:8080

}

// @tests non-privileged port for WebApp:Web
// TODO: implment test code here
