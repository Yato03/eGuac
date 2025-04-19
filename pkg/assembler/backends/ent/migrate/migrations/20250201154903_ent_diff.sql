-- Create "cvs_ss" table
CREATE TABLE "cvs_ss" ("id" uuid NOT NULL, "vuln_impact" double precision NOT NULL, "version" character varying NOT NULL, "attack_vector" character varying NOT NULL, PRIMARY KEY ("id"));
-- Create "cw_es" table
CREATE TABLE "cw_es" ("id" uuid NOT NULL, "vex_id" character varying NOT NULL, "name" character varying NOT NULL, "description" character varying NOT NULL, "background_detail" character varying NULL, PRIMARY KEY ("id"));
-- Modify "certify_vexes" table
ALTER TABLE "certify_vexes" ADD COLUMN "certify_vex_cvss" uuid NULL, ADD COLUMN "certify_vex_cwe" uuid NULL, ADD CONSTRAINT "certify_vexes_cvs_ss_cvss" FOREIGN KEY ("certify_vex_cvss") REFERENCES "cvs_ss" ("id") ON UPDATE NO ACTION ON DELETE SET NULL, ADD CONSTRAINT "certify_vexes_cw_es_cwe" FOREIGN KEY ("certify_vex_cwe") REFERENCES "cw_es" ("id") ON UPDATE NO ACTION ON DELETE SET NULL;
-- Create "consequences" table
CREATE TABLE "consequences" ("id" uuid NOT NULL, "notes" character varying NULL, "likelihood" character varying NULL, PRIMARY KEY ("id"));
-- Create "consequence_impacts" table
CREATE TABLE "consequence_impacts" ("id" uuid NOT NULL, "impact" character varying NOT NULL, PRIMARY KEY ("id"));
-- Create "consequence_consequence_impact" table
CREATE TABLE "consequence_consequence_impact" ("consequence_id" uuid NOT NULL, "consequence_impact_id" uuid NOT NULL, PRIMARY KEY ("consequence_id", "consequence_impact_id"), CONSTRAINT "consequence_consequence_impact_consequence_id" FOREIGN KEY ("consequence_id") REFERENCES "consequences" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "consequence_consequence_impact_consequence_impact_id" FOREIGN KEY ("consequence_impact_id") REFERENCES "consequence_impacts" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "consequence_scopes" table
CREATE TABLE "consequence_scopes" ("id" uuid NOT NULL, "scope" character varying NOT NULL, PRIMARY KEY ("id"));
-- Create "consequence_consequence_scope" table
CREATE TABLE "consequence_consequence_scope" ("consequence_id" uuid NOT NULL, "consequence_scope_id" uuid NOT NULL, PRIMARY KEY ("consequence_id", "consequence_scope_id"), CONSTRAINT "consequence_consequence_scope_consequence_id" FOREIGN KEY ("consequence_id") REFERENCES "consequences" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "consequence_consequence_scope_consequence_scope_id" FOREIGN KEY ("consequence_scope_id") REFERENCES "consequence_scopes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "cwe_consequence" table
CREATE TABLE "cwe_consequence" ("cwe_id" uuid NOT NULL, "consequence_id" uuid NOT NULL, PRIMARY KEY ("cwe_id", "consequence_id"), CONSTRAINT "cwe_consequence_consequence_id" FOREIGN KEY ("consequence_id") REFERENCES "consequences" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "cwe_consequence_cwe_id" FOREIGN KEY ("cwe_id") REFERENCES "cw_es" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "demonstrative_examples" table
CREATE TABLE "demonstrative_examples" ("id" uuid NOT NULL, "description" character varying NULL, PRIMARY KEY ("id"));
-- Create "cwe_demonstrative_example" table
CREATE TABLE "cwe_demonstrative_example" ("cwe_id" uuid NOT NULL, "demonstrative_example_id" uuid NOT NULL, PRIMARY KEY ("cwe_id", "demonstrative_example_id"), CONSTRAINT "cwe_demonstrative_example_cwe_id" FOREIGN KEY ("cwe_id") REFERENCES "cw_es" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "cwe_demonstrative_example_demonstrative_example_id" FOREIGN KEY ("demonstrative_example_id") REFERENCES "demonstrative_examples" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "detection_methods" table
CREATE TABLE "detection_methods" ("id" uuid NOT NULL, "detection_id" character varying NULL, "method" character varying NULL, "description" character varying NULL, "effectiveness" character varying NULL, PRIMARY KEY ("id"));
-- Create "cwe_detection_method" table
CREATE TABLE "cwe_detection_method" ("cwe_id" uuid NOT NULL, "detection_method_id" uuid NOT NULL, PRIMARY KEY ("cwe_id", "detection_method_id"), CONSTRAINT "cwe_detection_method_cwe_id" FOREIGN KEY ("cwe_id") REFERENCES "cw_es" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "cwe_detection_method_detection_method_id" FOREIGN KEY ("detection_method_id") REFERENCES "detection_methods" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "potential_mitigations" table
CREATE TABLE "potential_mitigations" ("id" uuid NOT NULL, "phase" character varying NULL, "description" character varying NULL, "effectiveness" character varying NULL, "effectiveness_notes" character varying NULL, PRIMARY KEY ("id"));
-- Create "cwe_potential_mitigation" table
CREATE TABLE "cwe_potential_mitigation" ("cwe_id" uuid NOT NULL, "potential_mitigation_id" uuid NOT NULL, PRIMARY KEY ("cwe_id", "potential_mitigation_id"), CONSTRAINT "cwe_potential_mitigation_cwe_id" FOREIGN KEY ("cwe_id") REFERENCES "cw_es" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "cwe_potential_mitigation_potential_mitigation_id" FOREIGN KEY ("potential_mitigation_id") REFERENCES "potential_mitigations" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
