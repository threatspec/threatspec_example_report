# threatspec project Threat Model

A threatspec project.


# Diagram
![Threat Model Diagram](ThreatModel.md.png)


# Threats

| Type | Component | Threat | Description | Test Count | File | Source |
| ---- | --------- | ------ | ----------- | ---------- | ---- | ------ |
| Exposure | WebApp:App | Cross-site Scripting | insufficient input validation | | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:72 | func editHandler(w http.ResponseWriter, r *http.Request, title string) {
    p, err := loadPage(title)
    if err != nil {
        p = &Page{Title: title}
    }
 |
| Exposure | WebApp:App | content injection | insufficient input validation | | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:81 | func saveHandler(w http.ResponseWriter, r *http.Request, title string) {
    body := r.FormValue("body")
    p := &Page{Title: title, Body: []byte(body)}
    err := p.save()
    if err != nil {
 |
| Acceptance | WebApp:FileSystem | arbitrary file writes | filename restrictions that limit the possible filenames written to by an attacker | | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:43 | func (p *Page) save() error {
    filename := p.Title + ".txt"
    return ioutil.WriteFile(filename, p.Body, 0600)
}

 |
| Acceptance | WebApp:FileSystem | arbitrary file reads | filename restrictions | | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:53 | func loadPage(title string) (*Page, error) {
    filename := title + ".txt"
    body, err := ioutil.ReadFile(filename)
    if err != nil {
        return nil, err
 |
| Transfer | User:Browser (from WebApp:Web) | @cwe_319_cleartext_transmission | non-sensitive information | | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:117 | func main() {
    flag.Parse()
    http.HandleFunc("/view/", makeHandler(viewHandler))
    http.HandleFunc("/edit/", makeHandler(editHandler))
    http.HandleFunc("/save/", makeHandler(saveHandler))
 |
| Mitigation | WebApp:Web | resource access abuse | basic input validation | 0 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:104 | func makeHandler(fn func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        m := validPath.FindStringSubmatch(r.URL.Path)
        if m == nil {
            http.NotFound(w, r)
 |
| Mitigation | WebApp:Web | privilege escalation | non-privileged port | 1 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:116 | func main() {
    flag.Parse()
    http.HandleFunc("/view/", makeHandler(viewHandler))
    http.HandleFunc("/edit/", makeHandler(editHandler))
    http.HandleFunc("/save/", makeHandler(saveHandler))
 |


# Tests

| Component | Control | Test | File |
| --------- | ------- | ---- | ---- |
| WebApp:Web | non-privileged port |  | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:142 |


# Reviews

| Component | Details | Filename | Line | Code |
| --------- | ------- | -------- | ---- | ---- |
| WebApp:Web | Is this a security feature? | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go | 129 |         if err != nil {
            log.Fatal(err)
        }
        s := &http.Server{}
        s.Serve(l)
 |


# Connections

| Source Component | Destination Component | Description | File | Source |
| ---------------- | --------------------- | ----------- | ---- | ------ |
| User:Browser | WebApp:Web | HTTP:8080 | /home/zeroxten/Downloads/src/threatspec/threatspec_example_report/simple_web.go:138 |  |
