/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package postgres_test

import (
	"fmt"
	"testing"

	. "github.com/onsi/gomega"

	infraApi "github.com/opendatahub-io/opendatahub-db-operator/api/infrastructure/v1alpha1"
	"github.com/opendatahub-io/opendatahub-db-operator/pkg/postgres"
)

func openPool(t *testing.T, cfg postgres.Config) postgres.Client {
	t.Helper()
	pool, err := postgres.NewClient(t.Context(), cfg)
	if err != nil {
		t.Fatalf("opening client: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// TestDDL_CreateDropSchema verifies CreateSchema and DropSchemaCascade are
// idempotent, and CreateSchema does not write an ownership marker.
func TestDDL_CreateDropSchema(t *testing.T) {
	g := NewWithT(t)
	cfg := startPostgres(t)

	ctx := t.Context()
	pool := openPool(t, cfg)

	g.Expect(postgres.CreateSchema(ctx, pool, "myschema")).To(Succeed())
	// Second call is idempotent
	g.Expect(postgres.CreateSchema(ctx, pool, "myschema")).To(Succeed())

	uid, err := postgres.SchemaOwnerClaimUID(ctx, pool, "myschema")
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(uid).To(BeEmpty())

	// Drop -- also idempotent
	g.Expect(postgres.DropSchemaCascade(ctx, pool, "myschema")).To(Succeed())
	g.Expect(postgres.DropSchemaCascade(ctx, pool, "myschema")).To(Succeed())
}

func TestDDL_CreateSchemaExclusiveWithOwner(t *testing.T) {
	g := NewWithT(t)
	cfg := startPostgres(t)

	ctx := t.Context()
	pool := openPool(t, cfg)

	g.Expect(postgres.CreateSchemaExclusiveWithOwner(ctx, pool, "owned_schema", "claim-uid-1")).To(Succeed())
	uid, err := postgres.SchemaOwnerClaimUID(ctx, pool, "owned_schema")
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(uid).To(Equal("claim-uid-1"))

	err = postgres.CreateSchemaExclusiveWithOwner(ctx, pool, "owned_schema", "claim-uid-2")
	g.Expect(postgres.IsDuplicateSchema(err)).To(BeTrue())

	g.Expect(postgres.DropSchemaCascade(ctx, pool, "owned_schema")).To(Succeed())
}

func TestDDL_EnsureDropRole(t *testing.T) {
	g := NewWithT(t)
	cfg := startPostgres(t)

	ctx := t.Context()
	pool := openPool(t, cfg)

	pw, err := postgres.GeneratePassword(24)
	g.Expect(err).NotTo(HaveOccurred())

	// Idempotent create
	g.Expect(postgres.EnsureRole(ctx, pool, "testrole", pw)).To(Succeed())
	g.Expect(postgres.EnsureRole(ctx, pool, "testrole", pw)).To(Succeed())

	// Verify the role can actually connect
	roleCfg := postgres.Config{
		Host: cfg.Host, Port: cfg.Port,
		User: "testrole", Password: pw, DBName: cfg.DBName,
	}
	roleClient := openPool(t, roleCfg)
	g.Expect(roleClient.Ping(ctx)).To(Succeed())

	// Idempotent drop
	g.Expect(postgres.DropRole(ctx, pool, "testrole")).To(Succeed())
	g.Expect(postgres.DropRole(ctx, pool, "testrole")).To(Succeed())

	// Connection with dropped role must fail
	roleClient = openPool(t, roleCfg)
	err = roleClient.Ping(ctx)
	g.Expect(err).To(HaveOccurred())
}

// TestDDL_ClaimCleanupDropsRoleWithOwnedObjects exercises the DatabaseClaim
// cleanup sequence: a ReadWrite role that created objects cannot be dropped
// until ownership is cleared, and after cleanup the role cannot log in.
func TestDDL_ClaimCleanupDropsRoleWithOwnedObjects(t *testing.T) {
	g := NewWithT(t)
	cfg := startPostgres(t)

	ctx := t.Context()
	admin := openPool(t, cfg)

	pw, err := postgres.GeneratePassword(24)
	g.Expect(err).NotTo(HaveOccurred())
	role := "owned_obj_role"
	g.Expect(postgres.EnsureRole(ctx, admin, role, pw)).To(Succeed())
	g.Expect(postgres.GrantDatabasePrivileges(ctx, admin, cfg.DBName, role, infraApi.AccessModeReadWrite)).To(Succeed())

	roleCfg := postgres.Config{
		Host: cfg.Host, Port: cfg.Port,
		User: role, Password: pw, DBName: cfg.DBName,
	}
	roleClient := openPool(t, roleCfg)
	_, err = roleClient.Exec(ctx, fmt.Sprintf("CREATE SCHEMA %s", postgres.QuoteIdentifier("owned_schema")))
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(roleClient.Ping(ctx)).To(Succeed())

	// DropRole fails while the role still owns objects.
	g.Expect(postgres.DropRole(ctx, admin, role)).NotTo(Succeed())

	g.Expect(postgres.ClearRoleOwnedObjects(ctx, admin, role, cfg.User)).To(Succeed())
	g.Expect(postgres.RevokeDatabasePrivileges(ctx, admin, cfg.DBName, role)).To(Succeed())
	g.Expect(postgres.DropRole(ctx, admin, role)).To(Succeed())

	exists, err := postgres.RoleExists(ctx, admin, role)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(exists).To(BeFalse())

	// Claim deletion must leave no usable login for the dropped role.
	// NewClient only builds a lazy pool; auth failure surfaces on Ping.
	dropped := openPool(t, roleCfg)
	g.Expect(dropped.Ping(ctx)).To(HaveOccurred())
}

// TestDDL_DropRoleTerminatesActiveSessions verifies claim cleanup can drop a
// role while a consumer connection is still open.
func TestDDL_DropRoleTerminatesActiveSessions(t *testing.T) {
	g := NewWithT(t)
	cfg := startPostgres(t)
	ctx := t.Context()
	admin := openPool(t, cfg)

	pw, err := postgres.GeneratePassword(24)
	g.Expect(err).NotTo(HaveOccurred())
	role := "live_session_role"
	g.Expect(postgres.EnsureRole(ctx, admin, role, pw)).To(Succeed())
	g.Expect(postgres.GrantDatabasePrivileges(ctx, admin, cfg.DBName, role, infraApi.AccessModeReadWrite)).To(Succeed())

	live := openPool(t, postgres.Config{
		Host: cfg.Host, Port: cfg.Port,
		User: role, Password: pw, DBName: cfg.DBName,
	})
	g.Expect(live.Ping(ctx)).To(Succeed())

	// Match claim cleanup: revoke privileges, then DropRole while the consumer
	// session is still open (DropRole terminates those backends first).
	g.Expect(postgres.RevokeDatabasePrivileges(ctx, admin, cfg.DBName, role)).To(Succeed())
	g.Expect(postgres.DropRole(ctx, admin, role)).To(Succeed())
	g.Expect(live.Ping(ctx)).To(HaveOccurred())

	exists, err := postgres.RoleExists(ctx, admin, role)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(exists).To(BeFalse())
}

// TestDDL_DropDatabaseWithActiveSession verifies DeletionPolicy=Delete can
// drop a database while a consumer is still connected (PG 16 WITH FORCE).
func TestDDL_DropDatabaseWithActiveSession(t *testing.T) {
	g := NewWithT(t)
	cfg := startPostgres(t)
	ctx := t.Context()
	admin := openPool(t, cfg)

	dbName := "claim_drop_db"
	g.Expect(postgres.CreateDatabase(ctx, admin, dbName)).To(Succeed())

	pw, err := postgres.GeneratePassword(24)
	g.Expect(err).NotTo(HaveOccurred())
	role := "claim_drop_db_role"
	g.Expect(postgres.EnsureRole(ctx, admin, role, pw)).To(Succeed())
	g.Expect(postgres.GrantDatabasePrivileges(ctx, admin, dbName, role, infraApi.AccessModeReadWrite)).To(Succeed())

	live := openPool(t, postgres.Config{
		Host: cfg.Host, Port: cfg.Port,
		User: role, Password: pw, DBName: dbName,
	})
	g.Expect(live.Ping(ctx)).To(Succeed())

	g.Expect(postgres.DropDatabase(ctx, admin, dbName)).To(Succeed())
	g.Expect(live.Ping(ctx)).To(HaveOccurred())

	exists, err := postgres.DatabaseExists(ctx, admin, dbName)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(exists).To(BeFalse())

	g.Expect(postgres.DropRole(ctx, admin, role)).To(Succeed())
}

// TestDDL_GrantSchemaPrivileges verifies ReadWrite vs ReadOnly enforcement.
// Each subtest uses its own schema to avoid interference.
func TestDDL_GrantSchemaPrivileges(t *testing.T) {
	cfg := startPostgres(t)

	ctx := t.Context()
	pool := openPool(t, cfg)

	pw, _ := postgres.GeneratePassword(24)

	for _, tc := range []struct {
		name       string
		accessMode infraApi.AccessMode
		canWrite   bool
	}{
		{"readwrite", infraApi.AccessModeReadWrite, true},
		{"readonly", infraApi.AccessModeReadOnly, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			schema := "priv_" + tc.name
			role := "role_" + tc.name

			g.Expect(postgres.CreateSchema(ctx, pool, schema)).To(Succeed())
			t.Cleanup(func() { _ = postgres.DropSchemaCascade(ctx, pool, schema) })
			_, err := pool.Exec(ctx, fmt.Sprintf("CREATE TABLE %s.t (id int)", postgres.QuoteIdentifier(schema)))
			g.Expect(err).NotTo(HaveOccurred())
			_, err = pool.Exec(ctx, fmt.Sprintf("INSERT INTO %s.t VALUES (1)", postgres.QuoteIdentifier(schema)))
			g.Expect(err).NotTo(HaveOccurred())
			// Create before grants so ON ALL SEQUENCES covers the serial sequence.
			_, err = pool.Exec(ctx, fmt.Sprintf(
				"CREATE TABLE %s.serial_t (id serial PRIMARY KEY, name text)",
				postgres.QuoteIdentifier(schema),
			))
			g.Expect(err).NotTo(HaveOccurred())

			g.Expect(postgres.EnsureRole(ctx, pool, role, pw)).To(Succeed())
			g.Expect(postgres.GrantSchemaPrivileges(ctx, pool, schema, role, tc.accessMode)).To(Succeed())
			t.Cleanup(func() { _ = postgres.DropRole(ctx, pool, role) })

			roleCfg := postgres.Config{
				Host: cfg.Host, Port: cfg.Port,
				User: role, Password: pw, DBName: cfg.DBName,
			}
			rolePool, err := postgres.NewClient(ctx, roleCfg)
			g.Expect(err).NotTo(HaveOccurred())
			defer rolePool.Close()

			// SELECT must always work
			var count int
			row, err := rolePool.QueryRow(ctx,
				fmt.Sprintf("SELECT count(*) FROM %s.t", postgres.QuoteIdentifier(schema)),
			)
			g.Expect(err).NotTo(HaveOccurred())
			g.Expect(row.Scan(&count)).To(Succeed())
			g.Expect(count).To(Equal(1))

			// CREATE TABLE: allowed for ReadWrite, must fail for ReadOnly.
			_, createErr := rolePool.Exec(ctx,
				fmt.Sprintf("CREATE TABLE %s.created_by_claim (id int)", postgres.QuoteIdentifier(schema)))
			if tc.canWrite {
				g.Expect(createErr).To(Succeed(),
					fmt.Sprintf("readwrite role should be able to create tables: %v", createErr))
			} else {
				g.Expect(createErr).To(HaveOccurred(), "readonly role must not be able to create tables")
			}

			// serial inserts need sequence privileges, not only table DML.
			_, insertErr := rolePool.Exec(ctx, fmt.Sprintf(
				"INSERT INTO %s.serial_t (name) VALUES ('ada')",
				postgres.QuoteIdentifier(schema),
			))
			if tc.canWrite {
				g.Expect(insertErr).To(Succeed(),
					fmt.Sprintf("readwrite role should insert into serial tables: %v", insertErr))
			} else {
				g.Expect(insertErr).To(HaveOccurred(), "readonly role must not insert into serial tables")
				// ReadOnly must not get sequence USAGE (nextval advances the counter).
				_, nextErr := rolePool.Exec(ctx, fmt.Sprintf(
					"SELECT nextval(pg_get_serial_sequence(%s, 'id'))",
					postgres.QuoteLiteral(schema+".serial_t"),
				))
				g.Expect(nextErr).To(HaveOccurred(), "readonly role must not call nextval")
			}
		})
	}
}

func TestDDL_GrantDatabasePrivileges(t *testing.T) {
	cfg := startPostgres(t)

	ctx := t.Context()
	pool := openPool(t, cfg)

	for _, tc := range []struct {
		name       string
		accessMode infraApi.AccessMode
		canCreate  bool
	}{
		{"readwrite", infraApi.AccessModeReadWrite, true},
		{"readonly", infraApi.AccessModeReadOnly, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)

			role := "db_role_" + tc.name
			password, err := postgres.GeneratePassword(24)
			g.Expect(err).NotTo(HaveOccurred())

			g.Expect(postgres.EnsureRole(ctx, pool, role, password)).To(Succeed())
			g.Expect(postgres.GrantDatabasePrivileges(ctx, pool, cfg.DBName, role, tc.accessMode)).To(Succeed())
			t.Cleanup(func() { _ = postgres.DropRole(ctx, pool, role) })

			roleCfg := postgres.Config{
				Host:     cfg.Host,
				Port:     cfg.Port,
				User:     role,
				Password: password,
				DBName:   cfg.DBName,
			}
			rolePool, err := postgres.NewClient(ctx, roleCfg)
			g.Expect(err).NotTo(HaveOccurred())
			defer rolePool.Close()

			schema := "db_priv_" + tc.name
			_, createErr := rolePool.Exec(
				ctx,
				fmt.Sprintf("CREATE SCHEMA %s", postgres.QuoteIdentifier(schema)),
			)
			if tc.canCreate {
				g.Expect(createErr).To(Succeed(), fmt.Sprintf("readwrite role should be able to create schema: %v", createErr))
				t.Cleanup(func() { _ = postgres.DropSchemaCascade(ctx, pool, schema) })
			} else {
				g.Expect(createErr).To(HaveOccurred(), "readonly role must not be able to create schema")
			}
		})
	}
}

// TestDDL_DatabaseExists verifies the helper correctly identifies existing
// and non-existing databases.
func TestDDL_DatabaseExists(t *testing.T) {
	g := NewWithT(t)
	cfg := startPostgres(t)

	ctx := t.Context()
	pool := openPool(t, cfg)

	exists, err := postgres.DatabaseExists(ctx, pool, cfg.DBName)
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(exists).To(BeTrue())

	notExists, err := postgres.DatabaseExists(ctx, pool, "totally_nonexistent_db_xyz")
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(notExists).To(BeFalse())
}

func TestDDL_MissingExtensions(t *testing.T) {
	g := NewWithT(t)
	cfg := startPostgres(t)

	ctx := t.Context()
	pool := openPool(t, cfg)

	missing, err := postgres.MissingExtensions(ctx, pool, []string{"plpgsql", "totally_nonexistent_ext_xyz"})
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(missing).To(Equal([]string{"totally_nonexistent_ext_xyz"}))
}
