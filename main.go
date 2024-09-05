package main

import (
	"fmt"
	"time"

	ghelper "github.com/pharogrammer/pharogrammer/git"
)

func main() {
	// repoUrlPublic := "https://github.com/moh-amer/helm-app.git"
	// repoUrlPrivate := "https://github.com/moh-amer/jenkins-lab1-private.git"
	// cloneRepo(repoUrlPrivate, "./clone_here", githubToken)

	gitHubClient := ghelper.GetDefaultCred()
	// gitHubClient.CloneRepo(repoUrlPrivate, "new")
	// gitHubClient.Pull("new_clone", "main")
	err := gitHubClient.Pull("new", "main")
	fmt.Println(err)
	err = gitHubClient.Pull("new", "main")
	fmt.Println(err)

	time.Sleep(30 * time.Second)
	err = gitHubClient.Pull("new", "main")
	fmt.Println(err)
}
