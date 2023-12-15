package runner

import (
	context "context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/weaveworks/tf-controller/internal/storage"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
)

const (
	EncryptionKeyLength = 32
	MessageChunkSize    = 1024 * 1024 * 10
)

// CreateWorkspaceBlob archives and compresses using tar and gzip the .terraform directory and returns the tarball as a byte array
func (r *TerraformRunnerServer) CreateWorkspaceBlob(ctx context.Context, req *CreateWorkspaceBlobRequest) (*CreateWorkspaceBlobReply, error) {
	log := ctrl.LoggerFrom(ctx).WithName(loggerName)
	if req.TfInstance != r.InstanceID {
		err := fmt.Errorf("no TF instance found")
		log.Error(err, "no terraform")
		return nil, err
	}

	blob, sum, err := r.archiveAndEncrypt(ctx, req.Namespace, filepath.Join(req.WorkingDir, ".terraform"))
	if err != nil {
		log.Error(err, "unable to archive and encrypt wokspace cache")
		return nil, err
	}

	return &CreateWorkspaceBlobReply{
		Blob:           blob,
		Sha256Checksum: sum,
	}, nil
}

// CreateWorkspaceBlobStream archives and compresses using tar and gzip the .terraform directory and returns the tarball as a byte array
func (r *TerraformRunnerServer) CreateWorkspaceBlobStream(req *CreateWorkspaceBlobRequest, streamServer Runner_CreateWorkspaceBlobStreamServer) error {
	log := ctrl.Log
	// We dont' have context here... that's not good.
	// log := ctrl.LoggerFrom(ctx).WithName(loggerName)
	if req.TfInstance != r.InstanceID {
		err := fmt.Errorf("no TF instance found")
		log.Error(err, "no terraform")
		return err
	}

	blob, sum, err := r.archiveAndEncrypt(context.Background(), req.Namespace, filepath.Join(req.WorkingDir, ".terraform"))
	if err != nil {
		log.Error(err, "unable to archive and encrypt wokspace cache")
		return err
	}

	for idx := 0; idx < len(blob); idx += MessageChunkSize {
		eob := idx + MessageChunkSize
		if eob > len(blob) {
			eob = len(blob)
		}

		if err := streamServer.Send(&CreateWorkspaceBlobReply{Blob: blob[idx:eob]}); err != nil {
			return err
		}
	}

	return streamServer.Send(&CreateWorkspaceBlobReply{
		Blob:           []byte{},
		Sha256Checksum: sum,
	})
}

func (r *TerraformRunnerServer) archiveAndEncrypt(ctx context.Context, namespace, path string) ([]byte, []byte, error) {
	log := ctrl.LoggerFrom(ctx).WithName(loggerName)

	log.Info("archiving workspace directory", "dir", path)
	archivePath, err := storage.ArchiveDir(path)
	if err != nil {
		log.Error(err, "unable to archive .terraform directory")
		return nil, nil, fmt.Errorf("unable to archive .terraform directory: %w", err)
	}

	// Read archivePath into byte array.
	blob, err := os.ReadFile(archivePath)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to read archive file: %w", err)
	}

	// Read encryption secret.
	secretName := "tf-runner.cache-encryption"
	encryptionSecretKey := types.NamespacedName{Name: secretName, Namespace: namespace}
	var encryptionSecret v1.Secret

	log.Info("fetching secret key", "key", encryptionSecretKey)
	if err := r.Client.Get(ctx, encryptionSecretKey, &encryptionSecret); err != nil {
		return nil, nil, fmt.Errorf("unable to get encryption secret: %w", err)
	}

	// 256 bit AES encryption with Galois Counter Mode.
	log.Info("encrypting content")
	token := encryptionSecret.Data["token"]
	key := token[:EncryptionKeyLength]

	aesCipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create new AES cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(aesCipher)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to cretae new Galois Counter Mode cipher: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read random data as nonce: %w", err)
	}

	out := gcm.Seal(nonce, nonce, blob, nil)

	// SHA256 checksum so we can verify if the saved content is not corrupted.
	log.Info("generating sha256 checksum")
	sha := sha256.New()
	if _, err := sha.Write(out); err != nil {
		return nil, nil, fmt.Errorf("unable to write sha256 checksum: %w", err)
	}
	sum := sha.Sum(nil)

	return out, sum, nil
}
