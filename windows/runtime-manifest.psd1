@{
    SchemaVersion = 1

    Python = @{
        Version       = "3.11.9"
        Url           = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-embed-amd64.zip"
        FileName      = "python-3.11.9-embed-amd64.zip"
        Sha256        = "009d6bf7e3b2ddca3d784fa09f90fe54336d5b60f0e0f305c37f400bf83cfd3b"
        ArchiveType   = "zip"
        Destination   = "python"
        Executable    = "python.exe"
    }

    VictoriaMetrics = @{
        Version       = "1.106.1"
        Url           = "https://github.com/VictoriaMetrics/VictoriaMetrics/releases/download/v1.106.1/victoria-metrics-windows-amd64-v1.106.1.zip"
        FileName      = "victoria-metrics-windows-amd64-v1.106.1.zip"
        Sha256        = "5b7857a99b3cabb4c4450b64acb515acd665cd61ba32af0fdd22311002807745"
        ArchiveType   = "zip"
        Destination   = "victoriametrics"
        Executable    = "victoria-metrics-windows-amd64-prod.exe"
    }

    Grafana = @{
        Version       = "12.4.0"
        Url           = "https://dl.grafana.com/grafana/release/12.4.0/grafana_12.4.0_22325204712_windows_amd64.tar.gz"
        FileName      = "grafana_12.4.0_22325204712_windows_amd64.tar.gz"
        Sha256        = "689ab4d5b2e8a29511927976f4c9cde1fd089e0029c98d3cbf245a8f9e33b665"
        ArchiveType   = "tar.gz"
        Destination   = "grafana"
        RootDirectory = "grafana-12.4.0"
        Executable    = "bin\grafana.exe"
    }
}
