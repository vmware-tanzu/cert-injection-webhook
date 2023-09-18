// Copyright 2020-Present VMware, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"

	"github.com/vmware-tanzu/cert-injection-webhook/pkg/certs"
)

func main() {
	logger := log.New(os.Stdout, "", 0)

	tempLocal, err := ioutil.TempDir("", "local")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tempLocal)

	tempCerts, err := ioutil.TempDir("", "certs")
	if err != nil {
		log.Fatal(err)
	}
	defer os.RemoveAll(tempCerts)

	logger.Println("Create certificate...")
	file, err := os.Create(filepath.Join(tempLocal, "cert-injection-webhook.crt"))
	if err != nil {
		log.Fatal(err)
	}

	logger.Println("Parsing certificate...")
	caCerts, count, err := certs.Parse("CA_CERTS_DATA", os.Environ())
	if err != nil {
		log.Fatal(err)
	}

	logger.Printf("Populate %d certificate(s)...\n", count)
	_, err = file.WriteString(caCerts)
	if err != nil {
		log.Fatal(err)
	}

	err = file.Close()
	if err != nil {
		log.Fatal(err)
	}

	logger.Println("Update CA certificates...")
	cmd := exec.Command("update-ca-certificates", "--etccertsdir", tempCerts, "--localcertsdir", tempLocal)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatal(err)
	}
	logger.Println(string(out))

	logger.Println("Copying CA certificates...")
	err = CopyDir(tempCerts, "/workspace")
	if err != nil {
		log.Fatal(err)
	}

	logger.Println("Finished setting up CA certificates")
}

func CopyDir(src string, dest string) error {
	var (
		err  error
		fds  []os.FileInfo
		info os.FileInfo
	)

	if info, err = os.Stat(src); err != nil {
		return err
	}

	if err = os.MkdirAll(dest, info.Mode()); err != nil {
		return err
	}

	if fds, err = ioutil.ReadDir(src); err != nil {
		return err
	}

	for _, fd := range fds {
		srcPath := path.Join(src, fd.Name())
		destPath := path.Join(dest, fd.Name())

		if fd.IsDir() {
			if err = CopyDir(srcPath, destPath); err != nil {
				return err
			}
		} else {
			if err = CopyFile(srcPath, destPath); err != nil {
				return err
			}
		}
	}

	return nil
}

func CopyFile(src, dest string) error {
	var (
		err      error
		srcFile  *os.File
		destFile *os.File
		info     os.FileInfo
	)

	if srcFile, err = os.Open(src); err != nil {
		return err
	}
	defer srcFile.Close()

	if destFile, err = os.Create(dest); err != nil {
		return err
	}
	defer destFile.Close()

	if _, err = io.Copy(destFile, srcFile); err != nil {
		return err
	}

	if info, err = os.Stat(src); err != nil {
		return err
	}

	return os.Chmod(dest, info.Mode())
}
