DELETE FROM dojo_challenges
WHERE id not IN (SELECT a.id FROM (SELECT id,name,category,count(*) AS c FROM challenges GROUP BY name,category ORDER BY id) as a);

DELETE FROM challenges
WHERE id not IN (SELECT a.id FROM (SELECT id,name,category,count(*) AS c FROM challenges GROUP BY name,category ORDER BY id) as a);
