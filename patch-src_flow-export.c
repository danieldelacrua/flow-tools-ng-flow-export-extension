--- src/flow-export.c.orig	2009-02-10 16:31:45.000000000 +0700
+++ src/flow-export.c	2015-06-03 17:54:17.000000000 +0700
@@ -86,6 +86,8 @@
 
 struct options {
   char dbaseURI[256];
+  char cfield[1024];
+  int numeric_ip;
   uint32_t cflowd_mask;
   uint64_t ft_mask;
   u_long records;
@@ -105,7 +107,7 @@
 int ftxfield_tocflow(uint64_t xfields, uint32_t *cfmask);
 
 int fmt_xfields_val(char *fmt_buf, char *rec, struct fts3rec_offsets *fo,
-  uint64_t xfields, int quote);
+  uint64_t xfields, int quote, int numeric_ip);
 int fmt_xfields_type(char *buf, uint64_t xfield);
 
 void usage(void);
@@ -128,6 +130,7 @@
 
   debug = 0;
   format_index = 0;
+  opt.numeric_ip = 0;
   bzero(&opt, sizeof opt);
   ascii_mask = 0;
 
@@ -137,7 +140,7 @@
   /* profile */
   ftprof_start (&ftp);
 
-  while ((i = getopt(argc, argv, "h?d:f:m:u:")) != -1)
+  while ((i = getopt(argc, argv, "nh?d:c:f:m:u:")) != -1)
 
     switch (i) {
 
@@ -145,6 +148,10 @@
       debug = atoi(optarg);
       break;
 
+    case 'n': /* debug */
+      opt.numeric_ip = 1;
+      break;
+
     case 'f': /* format */
       format_index = atoi(optarg);
       break;
@@ -170,6 +177,13 @@
       if (strlen(optarg) >= sizeof (opt.dbaseURI))
         fterr_errx(1, "dbaseURI string too long.");
       strcpy(opt.dbaseURI, optarg);
+
+      break;
+
+    case 'c': /* custom db field */
+      if (strlen(optarg) >= sizeof(opt.cfield))
+        fterr_errx(1, "custom field string too long.");
+      strcpy(opt.cfield, optarg);
       break;
 
     default:
@@ -196,7 +210,7 @@
     fterr_errx(1, "ftio_init(): failed");
 
   ret = format[format_index].where(&ftio, &opt);
-      
+
   if ((!ret) && (debug > 0)) {
     ftprof_end(&ftp, ftio_get_rec_total(&ftio));
     ftprof_print(&ftp, argv[0], stderr);
@@ -204,7 +218,7 @@
 
   fprintf(stderr, "%s: Exported %lu records\n", argv[0], opt.records);
 
-        
+
   return ret;
 
 } /* main */
@@ -506,7 +520,7 @@
   char buf[1024];
   char *rec;
 
-  if (ftio_check_xfield(ftio, FT_XFIELD_TOS | FT_XFIELD_PROT | 
+  if (ftio_check_xfield(ftio, FT_XFIELD_TOS | FT_XFIELD_PROT |
     FT_XFIELD_SRCADDR | FT_XFIELD_DSTADDR | FT_XFIELD_SRCPORT |
     FT_XFIELD_DSTPORT |
     FT_XFIELD_UNIX_SECS | FT_XFIELD_UNIX_NSECS |
@@ -516,7 +530,7 @@
   }
 
   ftio_get_ver(ftio, &ftv);
- 
+
   fts3rec_compute_offsets(&fo, &ftv);
 
   if (gettimeofday(&now, &tz) < 0) {
@@ -532,7 +546,7 @@
   bzero(&pd4, sizeof pd4); /* UDP */
   bsize = 0;
 
-  pfh.magic = TCPDUMP_MAGIC;  
+  pfh.magic = TCPDUMP_MAGIC;
   pfh.version_major = TCPDUMP_VERSION_MAJOR;
   pfh.version_minor = TCPDUMP_VERSION_MINOR;
   pfh.sigfigs = 6;
@@ -666,7 +680,7 @@
   } /* while */
 
   return 0;
-  
+
 } /* format1 */
 
 /*
@@ -695,7 +709,7 @@
 
   while ((rec = ftio_read(ftio))) {
 
-    len = fmt_xfields_val(fmt_buf, rec, &fo, opt->ft_mask, 0);
+    len = fmt_xfields_val(fmt_buf, rec, &fo, opt->ft_mask, 0, opt->numeric_ip);
 
     if (len)
       printf("%s\n", fmt_buf);
@@ -705,8 +719,8 @@
   } /* while */
 
   return 0;
- 
-} /* format2 */ 
+
+} /* format2 */
 
 /*
  * function: format3
@@ -719,8 +733,9 @@
   struct fts3rec_offsets fo;
   struct ftver ftv;
   char fields[1024], values[1024], query[3*1024];
+  char *cf_name, *cf_data;
   char *rec;
-  char *db_host, *db_name, *db_table, *db_user, *db_pwd, *db_tmp, *tmp;
+  char *db_host, *db_name, *db_table, *db_user, *db_pwd, *db_tmp, *tmp, *ctmp;
   int db_port;
   int len;
 
@@ -733,6 +748,9 @@
   db_table = MYSQL_DEFAULT_DBTABLE;
   db_pwd = MYSQL_DEFAULT_DBPWD;
 
+  cf_name = "";
+  cf_data = "";
+
   /* parse URI string */
 
   if (strlen(opt->dbaseURI)) {
@@ -754,6 +772,19 @@
 
   } /* dbaseURI */
 
+  /* parse custom fields string */
+  if (strlen(opt->cfield)) {
+    ctmp = opt->cfield;
+
+    cf_name = strsep(&ctmp, ":");
+    cf_data = strsep(&ctmp, ":");
+
+    if (!cf_name || !cf_data) {
+      fterr_warnx("Missing field in custom field, expecting name:data.");
+      return -1;
+    }
+  }
+
   ftio_get_ver(ftio, &ftv);
 
   fts3rec_compute_offsets(&fo, &ftv);
@@ -771,14 +802,14 @@
   if (mysql_options(&mysql, MYSQL_READ_DEFAULT_GROUP, "simple"))
     fterr_errx(1, "mysql_options(): %s", mysql_error(&mysql));
 
-  if (mysql_real_connect(&mysql, db_host, db_user, db_pwd, 
-	db_name, db_port, NULL, 0) == NULL) 
+  if (mysql_real_connect(&mysql, db_host, db_user, db_pwd,
+	db_name, db_port, NULL, 0) == NULL)
     fterr_errx(1,"mysql_real_connect(): %s\n", mysql_error(&mysql));
 
   /* foreach flow */
   while ((rec = ftio_read(ftio))) {
 
-    len = fmt_xfields_val(values, rec, &fo, opt->ft_mask, 1);
+    len = fmt_xfields_val(values, rec, &fo, opt->ft_mask, 1, opt->numeric_ip);
 
     /* form SQL query and execute it */
     if (len) {
@@ -786,15 +817,17 @@
       strcat (query, db_table);
       strcat (query, "(");
       strcat (query, fields);
+      if (cf_name != "" && cf_data != "") { strcat(query,","); strcat(query, cf_name); }
       strcat (query, ") VALUES (");
       strcat (query, values);
+      if (cf_name != "" && cf_data != "") { strcat(query,","); strcat(query, cf_data); }
       strcat (query, ")");
 
       if (debug)
         fprintf(stderr, "field=%s\n val=%s\n query=%s\n", fields, values,
           query);
 
-      if (mysql_real_query(&mysql, query, strlen(query)) != 0) 
+      if (mysql_real_query(&mysql, query, strlen(query)) != 0)
         fterr_warnx("mysql_real_query(): %s", mysql_error(&mysql));
 
     }
@@ -813,8 +846,8 @@
 #endif /* MYSQL */
 
   return 0;
- 
-} /* format3 */ 
+
+} /* format3 */
 
 /*
  * function: format4
@@ -846,9 +879,9 @@
  *   ret > 0 then encode another
  *   ret < 0 then this encoding failed, send and clear out buffer
 */
-  
-    if (ret <= 0) { 
-    
+
+    if (ret <= 0) {
+
       /* convert pdu to network byte order */
 #if BYTE_ORDER == LITTLE_ENDIAN
       ftpdu_swap(fte.buf_enc, BYTE_ORDER);
@@ -859,8 +892,8 @@
 
       /* reset encode buffer */
       ftencode_reset(&fte);
- 
-      /* if ret < 0 then the current record was not encoded */   
+
+      /* if ret < 0 then the current record was not encoded */
       if (ret < 0)
         goto retry;
     }
@@ -895,8 +928,9 @@
   struct fts3rec_offsets fo;
   struct ftver ftv;
   char fields[1024], values[1024], query[3*1024];
+  char *cf_name, *cf_data;
   char *rec;
-  char *db_host, *db_name, *db_table, *db_user, *db_pwd, *db_tmp, *tmp;
+  char *db_host, *db_name, *db_table, *db_user, *db_pwd, *db_tmp, *tmp, *ctmp;
   char *db_port;
   int len;
 
@@ -910,6 +944,9 @@
   db_table = POSTGRESQL_DEFAULT_DBTABLE;
   db_pwd = POSTGRESQL_DEFAULT_DBPWD;
 
+  cf_name = "";
+  cf_data = "";
+
   /* parse URI string */
 
   if (strlen(opt->dbaseURI)) {
@@ -930,6 +967,19 @@
 
   } /* dbaseURI */
 
+  /* parse custom fields string */
+  if (strlen(opt->cfield)) {
+    ctmp = opt->cfield;
+
+    cf_name = strsep(&ctmp, ":");
+    cf_data = strsep(&ctmp, ":");
+
+    if (!cf_name || !cf_data) {
+      fterr_warnx("Missing field in custom fields string, expecting name[,name2]:data[,data2].");
+      return -1;
+    }
+  }
+
   ftio_get_ver(ftio, &ftv);
 
   fts3rec_compute_offsets(&fo, &ftv);
@@ -943,13 +993,13 @@
   /* open PostgreSQL database */
   conn = PQsetdbLogin(db_host, db_port, (char *) NULL, (char *) NULL, db_name, db_user, db_pwd);
 
-  if (PQstatus(conn) == CONNECTION_BAD) 
+  if (PQstatus(conn) == CONNECTION_BAD)
     fterr_errx(1,"PQsetdbLogin(): %s\n", PQerrorMessage(conn));
 
   /* foreach flow */
   while ((rec = ftio_read(ftio))) {
 
-    len = fmt_xfields_val(values, rec, &fo, opt->ft_mask, 1);
+    len = fmt_xfields_val(values, rec, &fo, opt->ft_mask, 1, opt->numeric_ip);
 
     /* form SQL query and execute it */
     if (len) {
@@ -957,8 +1007,10 @@
       strcat (query, db_table);
       strcat (query, "(");
       strcat (query, fields);
+      if (cf_name != "" && cf_data != "") { strcat(query,","); strcat(query, cf_name); }
       strcat (query, ") VALUES (");
       strcat (query, values);
+      if (cf_name != "" && cf_data != "") { strcat(query,","); strcat(query, cf_data); }
       strcat (query, ")");
 
       if (debug)
@@ -989,8 +1041,8 @@
 #endif /* PGSQL */
 
   return 0;
- 
-} /* format5 */ 
+
+} /* format5 */
 
 int fmt_xfields_type(char *buf, uint64_t xfield)
 {
@@ -1202,7 +1254,7 @@
 
 
 int fmt_xfields_val(char *fmt_buf, char *rec, struct fts3rec_offsets *fo,
-  uint64_t xfields, int quote)
+  uint64_t xfields, int quote, int numeric_ip)
 {
   int comma, len;
 
@@ -1234,8 +1286,11 @@
   if (xfields & FT_XFIELD_EXADDR) {
     if (comma) fmt_buf[len++] = ',';
     if (quote) fmt_buf[len++] = '\'';
-    len += fmt_ipv4(fmt_buf+len, *((uint32_t*)(rec+fo->exaddr)),
-      FMT_JUST_LEFT);
+    if (numeric_ip) {
+      len += fmt_uint32(fmt_buf+len, *((uint32_t*)(rec+fo->exaddr)), FMT_JUST_LEFT);
+    } else {
+      len += fmt_ipv4(fmt_buf+len, *((uint32_t*)(rec+fo->exaddr)), FMT_JUST_LEFT);
+    }
     if (quote) fmt_buf[len++] = '\'';
     comma = 1;
   }
@@ -1292,8 +1347,11 @@
   if (xfields & FT_XFIELD_SRCADDR) {
     if (comma) fmt_buf[len++] = ',';
     if (quote) fmt_buf[len++] = '\'';
-    len += fmt_ipv4(fmt_buf+len, *((uint32_t*)(rec+fo->srcaddr)),
-      FMT_JUST_LEFT);
+    if (numeric_ip) {
+      len += fmt_uint32(fmt_buf+len, *((uint32_t*)(rec+fo->srcaddr)), FMT_JUST_LEFT);
+    } else {
+      len += fmt_ipv4(fmt_buf+len, *((uint32_t*)(rec+fo->srcaddr)), FMT_JUST_LEFT);
+    }
     if (quote) fmt_buf[len++] = '\'';
     comma = 1;
   }
@@ -1301,8 +1359,11 @@
   if (xfields & FT_XFIELD_DSTADDR) {
     if (comma) fmt_buf[len++] = ',';
     if (quote) fmt_buf[len++] = '\'';
-    len += fmt_ipv4(fmt_buf+len, *((uint32_t*)(rec+fo->dstaddr)),
-      FMT_JUST_LEFT);
+    if (numeric_ip) {
+      len += fmt_uint32(fmt_buf+len, *((uint32_t*)(rec+fo->dstaddr)), FMT_JUST_LEFT);
+    } else {
+      len += fmt_ipv4(fmt_buf+len, *((uint32_t*)(rec+fo->dstaddr)), FMT_JUST_LEFT);
+    }
     if (quote) fmt_buf[len++] = '\'';
     comma = 1;
   }
@@ -1310,8 +1371,11 @@
   if (xfields & FT_XFIELD_NEXTHOP) {
     if (comma) fmt_buf[len++] = ',';
     if (quote) fmt_buf[len++] = '\'';
-    len += fmt_ipv4(fmt_buf+len, *((uint32_t*)(rec+fo->nexthop)),
-      FMT_JUST_LEFT);
+    if (numeric_ip) {
+      len += fmt_uint32(fmt_buf+len, *((uint32_t*)(rec+fo->nexthop)), FMT_JUST_LEFT);
+    } else {
+      len += fmt_ipv4(fmt_buf+len, *((uint32_t*)(rec+fo->nexthop)), FMT_JUST_LEFT);
+    }
     if (quote) fmt_buf[len++] = '\'';
     comma = 1;
   }
@@ -1410,8 +1474,11 @@
   if (xfields & FT_XFIELD_PEER_NEXTHOP) {
     if (comma) fmt_buf[len++] = ',';
     if (quote) fmt_buf[len++] = '\"';
-    len += fmt_ipv4(fmt_buf+len, *((uint32_t*)(rec+fo->peer_nexthop)),
-      FMT_JUST_LEFT);
+    if (numeric_ip) {
+      len += fmt_uint32(fmt_buf+len, *((uint32_t*)(rec+fo->peer_nexthop)), FMT_JUST_LEFT);
+    } else {
+      len += fmt_ipv4(fmt_buf+len, *((uint32_t*)(rec+fo->peer_nexthop)), FMT_JUST_LEFT);
+    }
     if (quote) fmt_buf[len++] = '\'';
     comma = 1;
   }
@@ -1419,8 +1486,11 @@
   if (xfields & FT_XFIELD_ROUTER_SC) {
     if (comma) fmt_buf[len++] = ',';
     if (quote) fmt_buf[len++] = '\'';
-    len += fmt_ipv4(fmt_buf+len, *((uint32_t*)(rec+fo->router_sc)),
-      FMT_JUST_LEFT);
+    if (numeric_ip) {
+      len += fmt_uint32(fmt_buf+len, *((uint32_t*)(rec+fo->router_sc)), FMT_JUST_LEFT);
+    } else {
+      len += fmt_ipv4(fmt_buf+len, *((uint32_t*)(rec+fo->router_sc)), FMT_JUST_LEFT);
+    }
     if (quote) fmt_buf[len++] = '\'';
     comma = 1;
   }
@@ -1462,14 +1532,14 @@
 
 void usage(void) {
 
-  fprintf(stderr, "Usage: flow-export [-h] [-d debug_level] [-f format] [-m mask_fields] -u [database URI]\n");
+  fprintf(stderr, "Usage: flow-export [-h] [-n] [-d debug_level] [-f format] [-m mask_fields] -u [database URI] -c [custom fields]\n");
 
 
 } /* usage */
 
 /*
  * function ftxfield_tocflow
- *    
+ *
  * convert flow-tools xfield bits to cflowd bits
  *
  * returns 0:  ok
@@ -1533,7 +1603,7 @@
 
   if ((xfields &
     (FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SYSUPTIME|
-    FT_XFIELD_FIRST)) == 
+    FT_XFIELD_FIRST)) ==
     (FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SYSUPTIME|
     FT_XFIELD_FIRST)) {
     xfields &= ~FT_XFIELD_NEXTHOP;
@@ -1543,7 +1613,7 @@
 
   if ((xfields &
     (FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SYSUPTIME|
-    FT_XFIELD_LAST)) == 
+    FT_XFIELD_LAST)) ==
     (FT_XFIELD_UNIX_SECS|FT_XFIELD_UNIX_NSECS|FT_XFIELD_SYSUPTIME|
     FT_XFIELD_LAST)) {
     xfields &= ~FT_XFIELD_NEXTHOP;
@@ -1621,6 +1691,5 @@
   }
 
   return 0;
- 
-} /* ftxfield_tocflow */
 
+} /* ftxfield_tocflow */
