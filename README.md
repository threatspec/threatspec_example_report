# threatspec_example_report

A full example report. See [ThreatModel.md](ThreatModel.md)

Created using the `simple_web.go` file from `https://github.com/threatspec/threatspec_examples`.

# Commands run

```
$ threatspec init
Initialising threatspec...

Threatspec has been initialised. You can now configure the project in this
repository by editing the following file:

    threatspec.yaml.
        
$ threatspec run
Running threatspec...

Threatspec has been run against the source files. The following threat mode file
has been created and contains the mitigations, acceptances, connections etc. for
the project:

    threatmodel/threatmodel.json

The following library files have also been create:

    threatmodel/threats.json threatmodel/controls.json threatmodel/components.json
        
$ threatspec report
Generating report...
The following threat model visualisation image has been created: ThreatModel.md.png
The following threat model markdown report has been created: ThreatModel.md
```
