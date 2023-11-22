package safe

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
	"golang.org/x/oauth2/google"
	"log"
)

type Client struct {
	*vault.Client
}

type Vault struct {
	Address        string
	Authentication string
	Path           string
	Credential     Credential
}

type Credential struct {
	Token    string
	RoleID   string
	SecretID string
}

type DatabaseCredentials struct {
	Username string
	Password string
	LeaseID  string
}

type AWSCredentials struct {
	AccessKey string
	SecretKey string
	Secret    *vault.Secret
}

type GCPCredentials struct {
	Data   *google.Credentials
	Secret *vault.Secret
}

func NewClient(config *Vault) (*Client, error) {
	client, err := vault.NewClient(vault.DefaultConfig())

	err = client.SetAddress(fmt.Sprintf(config.Address))
	if err != nil {
		return nil, err
	}

	log.Println("Client authenticating to Vault")
	switch config.Authentication {
	case "token":
		log.Println("Using token authentication")
		if len(client.Token()) > 0 {
			log.Println("Got token from VAULT_TOKEN")
			break
		} else if len(config.Credential.Token) > 0 {
			log.Println("Got token from config file")
			token := config.Credential.Token
			client.SetToken(token)
			break
		} else {
			return nil, errors.New("could not get Vault token")
		}
	case "approle":
		log.Println("using approle authentication")

		if len(config.Credential.RoleID) == 0 {
			return nil, errors.New("Role ID not found.")
		}

		if len(config.Credential.SecretID) == 0 {
			return nil, errors.New("Secret ID not found.")
		}

		data := map[string]interface{}{"role_id": config.Credential.RoleID, "secret_id": config.Credential.SecretID}
		secret, err := client.Logical().Write(fmt.Sprintf("auth/%s/login", config.Path), data)
		if err != nil {
			return nil, err
		}

		log.Printf("Metadata: %v", secret.Auth.Metadata)
		token := secret.Auth.ClientToken
		client.SetToken(token)

	default:
		return nil, fmt.Errorf("auth method %s is not supported", config.Authentication)
	}

	return &Client{client}, nil
}

func (c *Client) GetTLSConfig(path string, data map[string]interface{}) (*tls.Config, error) {
	secret, err := c.Logical().Write(path, data)
	if err != nil {
		return nil, err
	}

	parsedCertBundle, err := certutil.ParsePKIMap(secret.Data)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := parsedCertBundle.GetTLSConfig(certutil.TLSClient)
	if err != nil {
		return nil, err
	}

	return tlsConfig, nil

}

func (c *Client) RenewSecret(secret *vault.Secret) error {
	watcher, err := c.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret: secret,
	})
	if err != nil {
		log.Fatal(err)
	}

	go watcher.Start()
	defer watcher.Stop()

	for {
		select {
		case err := <-watcher.DoneCh():
			if err != nil {
				log.Fatal(err)
			}
			log.Fatalf("Failed to renew secret %s", secret.LeaseID)
		case watcher := <-watcher.RenewCh():
			log.Printf("Succesfully renewed secret %s", watcher.Secret.LeaseID)
		}
	}
}

func (c *Client) GetSecret(mountPath string, secretPath string) (*vault.KVSecret, error) {
	log.Printf("Getting secret: %s/data/%s", mountPath, secretPath)
	secret, err := c.KVv2(mountPath).Get(context.Background(), secretPath)
	if err != nil {
		return nil, err
	}

	if secret == nil || secret.Data == nil {
		return nil, errors.New(fmt.Sprintf("secret not found at path: %s/data/%s", mountPath, secretPath))
	}
	return secret, nil
}

func (c *Client) GetDatabaseCredentials(path string) (*DatabaseCredentials, error) {
	credentials, err := c.Logical().Read(path)
	if err != nil {
		return nil, err
	}

	go c.RenewSecret(credentials)

	return &DatabaseCredentials{
		Username: credentials.Data["username"].(string),
		Password: credentials.Data["password"].(string),
		LeaseID:  credentials.LeaseID,
	}, nil
}

func (c *Client) Encrypt(path string, plaintext string) (string, error) {
	encoded := base64.StdEncoding.EncodeToString([]byte(plaintext))
	data := map[string]interface{}{"plaintext": encoded}

	encrypted, err := c.Client.Logical().Write(path, data)
	if err != nil {
		return "", err
	}

	ciphertext := encrypted.Data["ciphertext"].(string)

	return ciphertext, nil
}

func (c *Client) Decrypt(path string, ciphertext string) (string, error) {
	decrypted, err := c.Logical().Write(path, map[string]interface{}{
		"ciphertext": ciphertext,
	})
	if err != nil {
		return "", err
	}

	decryptedData := decrypted.Data["plaintext"].(string)

	decoded, _ := base64.StdEncoding.DecodeString(decryptedData)

	return string(decoded), nil
}

func (c *Client) GetAWSCredentials(path string) (*AWSCredentials, error) {
	credentials, err := c.Logical().Read(path)
	if err != nil {
		return nil, err
	}

	go c.RenewSecret(credentials)

	return &AWSCredentials{
		AccessKey: credentials.Data["access_key"].(string),
		SecretKey: credentials.Data["secret_key"].(string),
		Secret:    credentials,
	}, nil
}

func (c *Client) GetGCPServiceAccount(path string) (*GCPCredentials, error) {
	secret, err := c.Client.Logical().Read(path)
	if err != nil {
		return nil, err
	}

	secretData, err := base64.StdEncoding.DecodeString(secret.Data["private_key_data"].(string))
	if err != nil {
		return nil, err
	}

	credentials, err := google.CredentialsFromJSON(context.Background(), secretData, "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		return nil, err
	}

	return &GCPCredentials{
		Data:   credentials,
		Secret: secret,
	}, nil
}
