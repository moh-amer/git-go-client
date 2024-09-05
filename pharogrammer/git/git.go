package ghelper

import (
	"encoding/json"
	"fmt"
	"io"
	reghttp "net/http"
	"os"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	jwt "github.com/golang-jwt/jwt/v5"
)

type AccessTokenResponse struct {
	Token string `json:"token"`
}

type GitHubCred struct {
	Host           string `json:"host"`
	Username       string `json:"username"`
	AppID          int64  `json:"app_id"`
	InstallationID int64  `json:"installation_id"`
	PrivateKeyPath string `json:"private_key_path"`
	gitHubToken    string
	expiresAt      time.Time
}

// Load your private key from a file
func (g *GitHubCred) loadPrivateKey() (*jwt.SigningMethodRSA, []byte, error) {
	privateKey, err := os.ReadFile(g.PrivateKeyPath)
	if err != nil {
		return nil, nil, err
	}
	return jwt.SigningMethodRS256, privateKey, nil
}

// Generate a JWT for GitHub App authentication
func (g *GitHubCred) generateJWT(pemKey []byte) (string, error) {
	now := time.Now()
	expiresAt := now.Add(10 * time.Minute)
	g.expiresAt = expiresAt

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iat": jwt.NewNumericDate(now.Add(-time.Minute)),
		"exp": jwt.NewNumericDate(expiresAt),
		"iss": g.AppID,
	})

	privateKey, _ := jwt.ParseRSAPrivateKeyFromPEM(pemKey)

	tokenString, err := token.SignedString(privateKey)

	// fmt.Println(tokenString)

	return tokenString, err
}

func (g *GitHubCred) getInstallationToken(jwtToken string) (string, error) {
	url := fmt.Sprintf("https://api.%s/app/installations/%d/access_tokens", g.Host, g.InstallationID)
	req, err := reghttp.NewRequest("POST", url, nil)
	if err != nil {
		return "", err
	}

	// Set the Authorization header with the JWT
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/vnd.github.v3+json")

	client := &reghttp.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != reghttp.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to get installation token: %s", string(body))
	}

	var tokenResponse AccessTokenResponse
	err = json.NewDecoder(resp.Body).Decode(&tokenResponse)
	if err != nil {
		return "", err
	}

	return tokenResponse.Token, nil
}

func (g *GitHubCred) initGitHubAuth() error {

	if !g.expiresAt.IsZero() {
		fmt.Println("generated before")
		if time.Now().Compare(g.expiresAt) == 1 {
			fmt.Println("Expired, requires re-auth")
		} else {
			return nil
		}
	}

	// Load the private key
	_, privateKey, err := g.loadPrivateKey()
	if err != nil {
		return err
	}

	// Generate the JWT
	jwtToken, err := g.generateJWT(privateKey)
	if err != nil {
		return err
	}

	fmt.Println("Generated JWT:", jwtToken)

	githubToken, err := g.getInstallationToken(jwtToken)
	if err != nil {
		return err
	}

	g.gitHubToken = githubToken

	fmt.Println("Generated Github Token:", githubToken)

	return nil
}

func GetDefaultCred() *GitHubCred {
	appID := int64(977832) // Replace with your GitHub App ID
	installationID := int64(54093598)
	privateKeyPath := "./keys/private-key.pem"

	defaultCred := &GitHubCred{
		Host:           "github.com",
		Username:       "cicd",
		AppID:          appID,
		InstallationID: installationID,
		PrivateKeyPath: privateKeyPath,
	}

	return defaultCred
}

func (g *GitHubCred) CloneRepo(repoURL string, path string) error {

	//initialize token
	err := g.initGitHubAuth()
	if err != nil {
		return err
	}

	_, err = git.PlainClone(path, false, &git.CloneOptions{
		URL:      repoURL,
		Progress: os.Stdout,
		Auth: &http.BasicAuth{
			Username: g.Username,    // Your GitHub username
			Password: g.gitHubToken, // Your GitHub personal access token (or password)
		},
	})
	if err != nil && err != git.ErrRepositoryAlreadyExists {
		return err
	}
	fmt.Println("Repository cloned successfully")
	return nil
}

func (g *GitHubCred) Pull(repo_path string, branch_name any) error {
	g.initGitHubAuth()
	if branch_name == nil {
		branch_name = "master"
	}
	// Open an existing repository
	repo, err := git.PlainOpen(repo_path)
	if err != nil {
		return err
	}

	// Get the working directory
	w, err := repo.Worktree()
	if err != nil {
		return err
	}

	// Pull the latest changes from the default branch
	err = w.Pull(&git.PullOptions{
		RemoteName: "origin",
		Auth: &http.BasicAuth{
			Username: g.Username,    // Your Git username
			Password: g.gitHubToken, // GitHub access token or password for authentication
		},
		ReferenceName: plumbing.NewBranchReferenceName(branch_name.(string)),
		SingleBranch:  true,
	})

	if err != nil && err != git.NoErrAlreadyUpToDate {
		return err
	}

	fmt.Println("Repository successfully pulled")
	return nil
}

func (g *GitHubCred) PushChanges(repo_path string) error {
	g.initGitHubAuth()
	// Open an existing repository
	repo, err := git.PlainOpen(repo_path)
	if err != nil {
		return err
	}

	err = repo.Push(&git.PushOptions{
		Auth: &http.BasicAuth{
			Username: g.Username,
			Password: g.gitHubToken,
		},
	})

	if err != nil {
		return err
	}

	fmt.Println("Changes successfully pushed")
	return nil
}

// Adding and committing changes
func CommitChanges(repo_path string, message string) error {
	// Open an existing repository
	repo, err := git.PlainOpen(repo_path)
	if err != nil {
		return err
	}

	w, err := repo.Worktree()
	if err != nil {
		return err
	}

	// Add all changes (like `git add .`)
	_, err = w.Add(".")
	if err != nil {
		return err
	}

	// Commit the changes
	_, err = w.Commit(message, &git.CommitOptions{
		Author: &object.Signature{
			Name:  "name",
			Email: "cicd@github.com",
			When:  time.Now(),
		},
	})

	if err != nil {
		return err
	}

	fmt.Println("Changes successfully committed")
	return nil
}
