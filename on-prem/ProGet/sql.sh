docker run --name proget-sql \
      -e 'ACCEPT_EULA=Y' -e 'MSSQL_SA_PASSWORD=Stifstof2020' \
      -e 'MSSQL_PID=Express' --net=proget --restart=unless-stopped \
      -d mcr.microsoft.com/mssql/server:2019-latest