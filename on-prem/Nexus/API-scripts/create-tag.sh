#!/bin/bash
curl -u admin:9bbbb1b5-d203-4dea-999d-943622f542bf -X POST --header 'Content-Type: application/json' http://localhost:7081/service/rest/v1/tags \
  -d '{
    "name": "passed-unittest",
    "attributes": {
        "jvm": "9",
        "built-by": "jenkins"
    }
}'
