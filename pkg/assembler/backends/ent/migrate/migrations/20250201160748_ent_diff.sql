-- Modify "certify_vexes" table
ALTER TABLE "certify_vexes" DROP COLUMN "certify_vex_cwe";
-- Create "certify_vex_cwe" table
CREATE TABLE "certify_vex_cwe" ("certify_vex_id" uuid NOT NULL, "cwe_id" uuid NOT NULL, PRIMARY KEY ("certify_vex_id", "cwe_id"), CONSTRAINT "certify_vex_cwe_certify_vex_id" FOREIGN KEY ("certify_vex_id") REFERENCES "certify_vexes" ("id") ON UPDATE NO ACTION ON DELETE CASCADE, CONSTRAINT "certify_vex_cwe_cwe_id" FOREIGN KEY ("cwe_id") REFERENCES "cw_es" ("id") ON UPDATE NO ACTION ON DELETE CASCADE);
