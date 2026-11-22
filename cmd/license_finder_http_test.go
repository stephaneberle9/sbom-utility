// SPDX-License-Identifier: Apache-2.0
/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// Replaces the retry sleep by a recorder so that the tests run without waiting.
func recordHttpSleeps(t *testing.T) *[]time.Duration {
	var sleeps []time.Duration
	originalSleep := httpSleep
	httpSleep = func(d time.Duration) { sleeps = append(sleeps, d) }
	t.Cleanup(func() { httpSleep = originalSleep })
	return &sleeps
}

// Serves the given statuses one per request; the last one repeats. Counts the requests.
func newSequenceServer(t *testing.T, statuses []int, retryAfter string) (*httptest.Server, *int32) {
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(atomic.AddInt32(&requests, 1))
		status := statuses[len(statuses)-1]
		if n <= len(statuses) {
			status = statuses[n-1]
		}
		if retryAfter != "" {
			w.Header().Set("Retry-After", retryAfter)
		}
		w.WriteHeader(status)
		if status == http.StatusOK {
			body, _ := io.ReadAll(r.Body)
			_, _ = w.Write(append([]byte("ok:"), body...))
		}
	}))
	t.Cleanup(server.Close)
	return server, &requests
}

func TestHttpGetRetriesTransientStatusThenSucceeds(t *testing.T) {
	sleeps := recordHttpSleeps(t)
	server, requests := newSequenceServer(t, []int{503, 429, 502, 200}, "")

	body, err := performHttpGetRequest(server.URL)
	if err != nil {
		t.Fatalf("expected success after retries, got: %v", err)
	}
	if string(body) != "ok:" {
		t.Errorf("unexpected body: `%s`", body)
	}
	if *requests != 4 {
		t.Errorf("expected 4 requests, actual %d", *requests)
	}
	expected := []time.Duration{httpRetryBaseDelay, 2 * httpRetryBaseDelay, 4 * httpRetryBaseDelay}
	if len(*sleeps) != len(expected) {
		t.Fatalf("expected backoff delays %v, actual %v", expected, *sleeps)
	}
	for i := range expected {
		if (*sleeps)[i] != expected[i] {
			t.Errorf("backoff delay %d: expected %v, actual %v", i, expected[i], (*sleeps)[i])
		}
	}
}

func TestHttpGetGivesUpAfterMaxAttempts(t *testing.T) {
	recordHttpSleeps(t)
	server, requests := newSequenceServer(t, []int{503}, "")

	_, err := performHttpGetRequest(server.URL)
	var statusErr *HttpStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected HttpStatusError 503, got: %v", err)
	}
	if int(*requests) != httpMaxAttempts {
		t.Errorf("expected %d requests, actual %d", httpMaxAttempts, *requests)
	}
}

func TestHttpGetDoesNotRetryPermanentStatus(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusUnauthorized, http.StatusForbidden} {
		sleeps := recordHttpSleeps(t)
		server, requests := newSequenceServer(t, []int{status}, "")

		_, err := performHttpGetRequest(server.URL)
		var statusErr *HttpStatusError
		if !errors.As(err, &statusErr) || statusErr.StatusCode != status {
			t.Fatalf("expected HttpStatusError %d, got: %v", status, err)
		}
		if *requests != 1 || len(*sleeps) != 0 {
			t.Errorf("status %d: expected 1 request and no sleep, actual %d requests, %d sleeps", status, *requests, len(*sleeps))
		}
	}
}

func TestHttpGetHonorsRetryAfter(t *testing.T) {
	sleeps := recordHttpSleeps(t)
	server, _ := newSequenceServer(t, []int{429, 200}, "7")

	if _, err := performHttpGetRequest(server.URL); err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if len(*sleeps) != 1 || (*sleeps)[0] != 7*time.Second {
		t.Errorf("expected one delay of 7s from Retry-After, actual %v", *sleeps)
	}
}

func TestHttpGetRetriesDroppedConnection(t *testing.T) {
	sleeps := recordHttpSleeps(t)
	var requests int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&requests, 1) == 1 {
			hijacker, _ := w.(http.Hijacker)
			conn, _, _ := hijacker.Hijack()
			_ = conn.Close()
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(server.Close)

	body, err := performHttpGetRequest(server.URL)
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if string(body) != "ok" || len(*sleeps) != 1 {
		t.Errorf("unexpected result: body `%s`, sleeps %v", body, *sleeps)
	}
}

func TestHttpPostFormResendsBodyOnRetry(t *testing.T) {
	recordHttpSleeps(t)
	server, requests := newSequenceServer(t, []int{500, 200}, "")

	body, err := performHttpPostFormRequest(server.URL, "request", []byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("expected success after retry, got: %v", err)
	}
	if string(body) != "ok:request=%7B%22a%22%3A1%7D" {
		t.Errorf("retried request lost its body: `%s`", body)
	}
	if *requests != 2 {
		t.Errorf("expected 2 requests, actual %d", *requests)
	}
}

func TestPreferTransientError(t *testing.T) {
	transient := &HttpStatusError{URL: "https://repo.example/a", StatusCode: http.StatusServiceUnavailable}
	notFound := &HttpStatusError{URL: "https://repo.example/b", StatusCode: http.StatusNotFound}

	if got := preferTransientError(transient, notFound); got != error(transient) {
		t.Errorf("a later 404 must not hide an earlier 503, got: %v", got)
	}
	if got := preferTransientError(notFound, transient); got != error(transient) {
		t.Errorf("a later 503 replaces an earlier 404, got: %v", got)
	}
	if got := preferTransientError(nil, notFound); got != error(notFound) {
		t.Errorf("first error is kept, got: %v", got)
	}
}

func TestHttpGetFailsFastWhenRetryAfterIsTooLong(t *testing.T) {
	sleeps := recordHttpSleeps(t)
	server, requests := newSequenceServer(t, []int{429}, "1473")

	_, err := performHttpGetRequest(server.URL)
	var statusErr *HttpStatusError
	if !errors.As(err, &statusErr) || statusErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected HttpStatusError 429, got: %v", err)
	}
	if *requests != 1 || len(*sleeps) != 0 {
		t.Errorf("expected 1 request and no sleep, actual %d requests, %d sleeps", *requests, len(*sleeps))
	}
}

func TestHttpGetSendsDedicatedUserAgent(t *testing.T) {
	var userAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent = r.Header.Get("User-Agent")
	}))
	t.Cleanup(server.Close)

	if _, err := performHttpGetRequest(server.URL); err != nil {
		t.Fatal(err)
	}
	if userAgent != HTTP_USER_AGENT {
		t.Errorf("User-Agent: expected `%s`, actual `%s`", HTTP_USER_AGENT, userAgent)
	}
}
