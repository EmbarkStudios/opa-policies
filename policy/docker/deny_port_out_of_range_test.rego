package docker


test_port_out_of_range {
    input := [
        {
            "Cmd": "from",
            "Flags": [],
            "JSON": false,
            "SubCmd": "",
            "Value": [
                "google/cloud-sdk:slim"
            ]
        },
        {
            "Cmd": "expose",
            "Flags": [],
            "JSON": false,
            "SubCmd": "",
            "Value": [
                "700000"
            ]
        },
    ]
    deny_port_out_of_range with input as input
}
