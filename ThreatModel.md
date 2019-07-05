# threatspec project Threat Model

A threatspec project.


# Diagram
![Threat Model Diagram](ThreatModel.md.png)


# Threats

| Type | Component | Threat | Description | Test Count | File | Source |
| ---- | --------- | ------ | ----------- | ---------- | ---- | ------ |
| Exposure | WebApp:App | XSS injection | insufficient input validation | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:53> | func editHandler(w http.ResponseWriter, r *http.Request, title string) { |
| Exposure | WebApp:App | content injection | insufficient input validation | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:62> | func saveHandler(w http.ResponseWriter, r *http.Request, title string) { |
| Exposure | WebApp:App | XSS injection | insufficient input validation | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:53> | func editHandler(w http.ResponseWriter, r *http.Request, title string) { |
| Exposure | WebApp:App | content injection | insufficient input validation | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:62> | func saveHandler(w http.ResponseWriter, r *http.Request, title string) { |
| Acceptance | WebApp:FileSystem | arbitrary file writes | filename restrictions | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:27 | func (p *Page) save() error { |
| Acceptance | WebApp:FileSystem | arbitrary file reads | filename restrictions | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:34 | func loadPage(title string) (*Page, error) { |
| Acceptance | WebApp:FileSystem | arbitrary file writes | filename restrictions | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:27 | func (p *Page) save() error { |
| Acceptance | WebApp:FileSystem | arbitrary file reads | filename restrictions | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:34 | func loadPage(title string) (*Page, error) { |
| Transfer | User:Browser (from WebApp:Web) | @cwe_319_cleartext_transmission | non-sensitive information | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:98 | func main() { |
| Transfer | User:Browser (from WebApp:Web) | @cwe_319_cleartext_transmission | non-sensitive information | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:98 | func main() { |
| Mitigation | WebApp:FileSystem | unauthorised access | strict file permissions | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:28 | func (p *Page) save() error { |
| Mitigation | WebApp:Web | resource access abuse | basic input validation | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:85 | func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc { |
| Mitigation | WebApp:Web | privilege escalation | non-privileged port | 2 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:97 | func main() { |
| Mitigation | WebApp:FileSystem | unauthorised access | strict file permissions | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:28 | func (p *Page) save() error { |
| Mitigation | WebApp:Web | resource access abuse | basic input validation | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:85 | func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc { |
| Mitigation | WebApp:Web | privilege escalation | non-privileged port | 2 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:97 | func main() { |


# Tests

| Component | Control | Test | File |
| --------- | ------- | ---- | ---- |
| WebApp:Web | non-privileged port | // TODO: implment test code here | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:123 |
| WebApp:Web | non-privileged port | // TODO: implment test code here | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:123 |


# Reviews

| Component | Details | Filename | Line | Code |
| --------- | ------- | -------- | ---- | ---- |
| WebApp:Web | Is this a security feature? | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go | 110 | err = ioutil.WriteFile("final-port.txt", []byte(l.Addr().String()), 0644) |
| WebApp:Web | Is this a security feature? | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go | 110 | err = ioutil.WriteFile("final-port.txt", []byte(l.Addr().String()), 0644) |


# Connections

| Source Component | Destination Component | Description | File | Source |
| ---------------- | --------------------- | ----------- | ---- | ------ |
| User:Browser | WebApp:Web | HTTP:8080 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:119 | http.ListenAndServe(":8080", nil) |
| User:Browser | WebApp:Web | HTTP:8080 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:119 | http.ListenAndServe(":8080", nil) |
