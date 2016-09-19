package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"

	"camlistore.org/pkg/misc/pinentry"
)

func main() {
	baseSession := session.Must(session.NewSessionWithOptions(session.Options{
		SharedConfigState: session.SharedConfigEnable,
	}))

	// first, get a session token using the MFA.
	// these credentials are cached and continued to be used if still valid.
	creds, err := getMFACreds(baseSession)
	if err != nil {
		log.Fatal(err)
	}
	until := func(t time.Time) time.Duration { return -time.Since(t) }
	log.Printf("Credentials expire in %v", until(*creds.Expiration))

	// second, assume the role. This happens every time, and is not
	// currently cached, since the credentials don't last very long by
	// default.
	arn := os.Getenv("AWS_ASSUME_ROLE")
	roleSessionName := os.Getenv("AWS_ASSUME_ROLE_SESSION_NAME")
	sess := sessionWithCredentials(baseSession, creds)
	creds, err = assumeRole(sess, arn, roleSessionName)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Role creds expire in %v", until(*creds.Expiration))

	args := os.Args[1:]
	if len(args) == 0 {
		printCreds(creds)
		return
	}
	err = runWithCreds(creds, args)
	if err != nil {
		log.Fatal(err)
	}
}

func printCreds(creds *sts.Credentials) {
	fmt.Print(
		"export",
		" AWS_ACCESS_KEY_ID=", *creds.AccessKeyId,
		" AWS_SECRET_ACCESS_KEY=", *creds.SecretAccessKey,
		" AWS_SESSION_TOKEN=", *creds.SessionToken,
		"\n",
	)
}

func runWithCreds(creds *sts.Credentials, args []string) error {
	os.Setenv("AWS_ACCESS_KEY_ID", *creds.AccessKeyId)
	os.Setenv("AWS_SECRET_ACCESS_KEY", *creds.SecretAccessKey)
	os.Setenv("AWS_SESSION_TOKEN", *creds.SessionToken)

	execPath, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}

	return syscall.Exec(execPath, args, os.Environ())
}

func sessionWithCredentials(sess *session.Session, c *sts.Credentials) *session.Session {
	return sess.Copy(
		sess.Config.WithCredentials(
			credentials.NewStaticCredentials(
				*c.AccessKeyId,
				*c.SecretAccessKey,
				*c.SessionToken,
			)))
}

func getMFACreds(sess *session.Session) (*sts.Credentials, error) {
	cached, ok, err := loadCache()
	if err != nil {
		return nil, err
	}
	if ok {
		return cached, nil
	}

	serial := os.Getenv("AWS_MFA_SERIAL")
	token, err := mfaPrompt(serial)
	if err == pinentry.ErrCancel {
		return nil, fmt.Errorf("PIN entry cancelled")
	} else if err != nil {
		return nil, err
	}

	creds, err := getSessionToken(sess, serial, token)
	if err != nil {
		return nil, err
	}

	err = saveCache(creds)
	if err != nil {
		return nil, fmt.Errorf("saveCache: %v", err)
	}
	return creds, err
}

func assumeRole(sess *session.Session, arn, sessionName string) (*sts.Credentials, error) {
	stsC := sts.New(sess)
	resp, err := stsC.AssumeRole(&sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(3600), // maximum
		RoleArn:         aws.String(arn),
		RoleSessionName: aws.String(sessionName),
	})
	if err != nil {
		return nil, err
	}
	return resp.Credentials, nil
}

func mfaPrompt(serial string) (string, error) {
	r := pinentry.Request{
		Prompt: "AWS MFA for " + os.Args[0],
		Desc:   "Enter MFA token for " + serial,
	}
	return r.GetPIN()
}

func getSessionToken(sess *session.Session, serial, token string) (*sts.Credentials, error) {
	stsC := sts.New(sess)
	resp, err := stsC.GetSessionToken(&sts.GetSessionTokenInput{
		SerialNumber: aws.String(serial),
		TokenCode:    aws.String(token),
	})
	if err != nil {
		return nil, err
	}
	return resp.Credentials, nil
}

func cachePath() string {
	return filepath.Join(os.Getenv("HOME"), ".aws", "credcache.json")
}

func loadCache() (*sts.Credentials, bool, error) {
	fd, err := os.Open(cachePath())
	switch {
	default:
		return nil, false, err
	case os.IsNotExist(err):
		return nil, false, err
	case err == nil:
		// OK
	}
	defer fd.Close()

	dec := json.NewDecoder(fd)
	var c sts.Credentials
	err = dec.Decode(&c)
	if err != nil {
		return nil, false, err
	}

	if c.Expiration.Before(time.Now()) {
		log.Printf("Cached credentials expired.")
		return nil, false, nil
	}

	remaining := -time.Since(*c.Expiration)
	if remaining < 1*time.Hour {
		log.Printf("Cached credentials expire in less than 1 hour, refreshing.")
		return nil, false, nil
	}

	return &c, true, nil
}

func saveCache(creds *sts.Credentials) error {
	fd, err := os.Create(cachePath())
	if err != nil {
		return err
	}
	defer fd.Close()

	enc := json.NewEncoder(fd)
	return enc.Encode(creds)
}
