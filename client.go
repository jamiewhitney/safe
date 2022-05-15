package safe

import (
	"crypto/tls"
	"errors"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/helper/certutil"
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

func NewClient(config *Vault) (*Client, error) {
	client, err := vault.NewClient(vault.DefaultConfig())
	//Set the address
	err = client.SetAddress(fmt.Sprintf(config.Address))
	if err != nil {
		return nil, err
	}

	//Auth to Vault
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
			return nil, errors.New("Could not get Vault token.")
		}
	case "approle":
		log.Println("Using approle authentication")

		//Check Mount
		if len(config.Credential.RoleID) == 0 {
			return nil, errors.New("Role ID not found.")
		}

		//Check Mount
		if len(config.Credential.SecretID) == 0 {
			return nil, errors.New("Secret ID not found.")
		}

		//Auth with approle vault
		data := map[string]interface{}{"role_id": config.Credential.RoleID, "secret_id": config.Credential.SecretID}
		secret, err := client.Logical().Write(fmt.Sprintf("auth/%s/login", config.Path), data)
		if err != nil {
			return nil, err
		}

		log.Printf("Metadata: %v", secret.Auth.Metadata)
		token := secret.Auth.ClientToken
		client.SetToken(token)

	default:
		return nil, fmt.Errorf("Auth method %s is not supported", config.Authentication)
	}

	return &Client{client}, nil
}

func (c *Client) GetTLSConfig(path string, data map[string]interface{}) (*tls.Config, error) {
	secret, err := c.Logical().Write(path, data)
	if err != nil {
		return nil, err
	}

	ParsedCertBundle, err := certutil.ParsePKIMap(secret.Data)
	if err != nil {
		return nil, err
	}

	tlsConfig, err := ParsedCertBundle.GetTLSConfig(certutil.TLSClient)
	if err != nil {
		return nil, err
	}

	return tlsConfig, nil

}

func (c *Client) RenewSecret(secret vault.Secret) error {
	watcher, err := c.NewLifetimeWatcher(&vault.LifetimeWatcherInput{
		Secret: &secret,
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
