-- 1. Query to detect high volume of failed login attempts from a single IP (Brute Force or Scanning)
-- This identifies sources that are repeatedly hitting the system.
SELECT
    ip_address,
    COUNT(*) AS failed_attempts_count,
    ARRAY_AGG(DISTINCT user_id) AS targeted_users
FROM
    authentication_logs_table
WHERE
    status = 'FAILED'
    AND timestamp >= (CURRENT_TIMESTAMP() - INTERVAL '30 minutes') -- Check failed attempts in the last 30 minutes
GROUP BY
    ip_address
HAVING
    COUNT(*) >= 10 -- Flag any IP with 10 or more failed attempts
ORDER BY
    failed_attempts_count DESC;

-- 2. Query to identify suspicious successful logins after a series of failures
-- This helps detect successful brute force or password spray attacks.
WITH FailedAttempts AS (
    SELECT user_id, MAX(timestamp) AS last_failure_time
    FROM authentication_logs_table
    WHERE status = 'FAILED'
    GROUP BY user_id
    HAVING COUNT(*) >= 3 -- At least 3 failures
)
SELECT
    t1.user_id,
    t1.ip_address,
    t1.timestamp AS successful_login_time,
    t2.last_failure_time
FROM
    authentication_logs_table AS t1
JOIN
    FailedAttempts AS t2
ON t1.user_id = t2.user_id
WHERE
    t1.status = 'SUCCESS'
    AND t1.timestamp BETWEEN t2.last_failure_time AND (t2.last_failure_time + INTERVAL '1 minute') -- Success within 1 minute of the last failure
ORDER BY
    successful_login_time DESC;

-- 3. Query to identify potential privilege escalation or data access abuse
-- This looks for sudden, unusual activity after a user receives a new role.
SELECT
    user_id,
    event_type,
    COUNT(*) AS event_count
FROM
    system_activity_logs
WHERE
    event_type IN ('DATA_DOWNLOAD', 'CONFIG_CHANGE')
    AND timestamp >= (CURRENT_TIMESTAMP() - INTERVAL '1 hour') -- Check for unusual activity in the last hour
GROUP BY
    user_id, event_type
HAVING
    COUNT(*) > 5
ORDER BY
    event_count DESC;
