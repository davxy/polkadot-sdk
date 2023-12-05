#!/bin/bash

function help() {
  echo "Usage: $0 <command>"
  echo "  Commands:"
  echo "  * keygen <phrase> : generate a new member keypair derived from <phrase>"
  echo "  * members: get members list"
  echo "  * open <member> : generate a commitment for <member>"
  echo "  * create <member> <message>: generate a commitment for <member> and <message>"
  exit
}

function keygen() {
  phrase=$1
  if [[ $phrase == "" ]]; then
    help
  fi
  echo "Generating key for secret phrase: $phrase"
  curl -H "Content-Type: application/json" \
       -d "{\"id\":1, \"jsonrpc\":\"2.0\", \"method\":\"verifiable_keygen\", \"params\":[\"$phrase\"]}" \
       http://localhost:9944 | jq
}

function members() {
  echo "Members to add to the ring"
  curl -H "Content-Type: application/json" \
       -d "{\"id\":1, \"jsonrpc\":\"2.0\", \"method\":\"verifiable_members\"}" \
       http://localhost:9944 | jq
}

function open() {
  member=$1
  if [[ $member == "" ]]; then
    help
  fi
  echo "Generating commitment for member: $member"
  curl -H "Content-Type: application/json" \
       -d "{\"id\":1, \"jsonrpc\":\"2.0\", \"method\":\"verifiable_open\", \"params\":[\"$member\"]}" \
       http://localhost:9944 | jq
}

function create() {
  member=$1
  message=$2
  if [[ $member == "" || $message == "" ]]; then
    help
  fi
  echo "Generating proof for member: $member"
  echo "Message: $message"
  curl -H "Content-Type: application/json" \
       -d "{\"id\":1, \"jsonrpc\":\"2.0\", \"method\":\"verifiable_create\", \"params\":[\"$member\", \"$message\"]}" \
       http://localhost:9944 | jq
}

case $1 in
  "keygen")
    keygen $2
    ;;
  "members")
    members
    ;;
  "open")
    open $2
    ;;
  "create")
    create $2 $3
    ;;
  *)
    help
    ;;
esac

