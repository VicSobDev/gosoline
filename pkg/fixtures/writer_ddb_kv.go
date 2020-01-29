package fixtures

import (
	"context"
	"fmt"
	"github.com/applike/gosoline/pkg/cfg"
	"github.com/applike/gosoline/pkg/kvstore"
	"github.com/applike/gosoline/pkg/mdl"
	"github.com/applike/gosoline/pkg/mon"
	"reflect"
)

type KvStoreFixture struct {
	Key   interface{}
	Value interface{}
}

type dynamoDbKvStoreFixtureWriter struct {
	logger mon.Logger
	store  kvstore.KvStore
}

func DynamoDbKvStoreFixtureWriterFactory(modelId *mdl.ModelId) FixtureWriterFactory {
	return func(config cfg.Config, logger mon.Logger) FixtureWriter {
		store := kvstore.NewDdbKvStore(config, logger, &kvstore.Settings{
			AppId: cfg.AppId{
				Project:     modelId.Project,
				Environment: modelId.Environment,
				Family:      modelId.Family,
				Application: modelId.Application,
			},
			Name: modelId.Name,
		})

		return NewDynamoDbKvStoreFixtureWriterWithInterfaces(logger, store)
	}
}

func NewDynamoDbKvStoreFixtureWriterWithInterfaces(logger mon.Logger, store kvstore.KvStore) FixtureWriter {
	return &dynamoDbKvStoreFixtureWriter{
		logger: logger,
		store:  store,
	}
}

func (d *dynamoDbKvStoreFixtureWriter) Write(fs *FixtureSet) error {
	for _, item := range fs.Fixtures {
		kvItem, ok := item.(*KvStoreFixture)

		if !ok {
			return fmt.Errorf("invalid fixture type: %s", reflect.TypeOf(item))
		}

		err := d.store.Put(context.Background(), kvItem.Key, kvItem.Value)

		if err != nil {
			return err
		}
	}

	d.logger.Infof("loaded %d dynamo db kv fixtures", len(fs.Fixtures))

	return nil
}