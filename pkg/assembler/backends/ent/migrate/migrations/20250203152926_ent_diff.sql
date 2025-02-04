-- Modify "certify_vexes" table
ALTER TABLE "certify_vexes" ADD COLUMN "priority" double precision NULL;
-- Create "exploits" table
CREATE TABLE "exploits" ("id" uuid NOT NULL, "exploit_id" character varying NULL, "description" character varying NULL, "payload" character varying NULL, PRIMARY KEY ("id"));
-- Create "certify_vex_exploit" table
CREATE TABLE "certify_vex_exploit" ("certify_vex_id" uuid NOT NULL, "exploit_id" uuid NOT NULL, PRIMARY KEY ("certify_vex_id", "exploit_id"), CONSTRAINT "certify_vex_exploit_certify_vex_id" FOREIGN KEY ("certify_vex_id") REFERENCES "certify_vexes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "certify_vex_exploit_exploit_id" FOREIGN KEY ("exploit_id") REFERENCES "exploits" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "reachable_codes" table
CREATE TABLE "reachable_codes" ("id" uuid NOT NULL, "path_to_file" character varying NULL, PRIMARY KEY ("id"));
-- Create "certify_vex_reachable_code" table
CREATE TABLE "certify_vex_reachable_code" ("certify_vex_id" uuid NOT NULL, "reachable_code_id" uuid NOT NULL, PRIMARY KEY ("certify_vex_id", "reachable_code_id"), CONSTRAINT "certify_vex_reachable_code_certify_vex_id" FOREIGN KEY ("certify_vex_id") REFERENCES "certify_vexes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "certify_vex_reachable_code_reachable_code_id" FOREIGN KEY ("reachable_code_id") REFERENCES "reachable_codes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
-- Create "reachable_code_artifacts" table
CREATE TABLE "reachable_code_artifacts" ("id" uuid NOT NULL, "artifact_name" character varying NULL, "used_in_lines" character varying NULL, PRIMARY KEY ("id"));
-- Create "reachable_code_reachable_code_artifact" table
CREATE TABLE "reachable_code_reachable_code_artifact" ("reachable_code_id" uuid NOT NULL, "reachable_code_artifact_id" uuid NOT NULL, PRIMARY KEY ("reachable_code_id", "reachable_code_artifact_id"), CONSTRAINT "reachable_code_reachable_code_artifact_reachable_code_artifact_" FOREIGN KEY ("reachable_code_artifact_id") REFERENCES "reachable_code_artifacts" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "reachable_code_reachable_code_artifact_reachable_code_id" FOREIGN KEY ("reachable_code_id") REFERENCES "reachable_codes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
