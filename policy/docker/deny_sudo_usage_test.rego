package docker

test_deny_sudo_usage {
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
            "Cmd": "run",
            "Flags": [],
            "JSON": false,
            "SubCmd": "",
            "Value": [
                "sudo apt-get udpate"
            ]
        },
    ]
    deny_sudo_usage with input as input
}
