docker exec -it proget-sql /opt/mssql-tools/bin/sqlcmd \
   -S localhost -U SA -P 'Stifstof2020' \
   -Q 'CREATE DATABASE [ProGet] COLLATE SQL_Latin1_General_CP1_CI_AS'