docker run -d -v proget-packages:/var/proget/packages -p 80:80 --net=proget \
    --name=proget --restart=unless-stopped \
    -e SQL_CONNECTION_STRING='Data Source=proget-sql; Initial Catalog=ProGet; User ID=sa; Password=Stifstof2020' \
    proget.inedo.com/productimages/inedo/proget:5.3.10
