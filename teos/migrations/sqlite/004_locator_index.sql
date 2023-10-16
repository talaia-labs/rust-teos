-- This index greatly enhances the performance of locator based selection queries:
-- "SELECT ... FROM appointments WHERE locator = ..."
CREATE INDEX IF NOT EXISTS locators_index ON appointments (
    locator
);
