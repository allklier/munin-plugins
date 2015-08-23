#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _XOPEN_SOURCE 500
#include <time.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <regex.h>

#define max(a,b)	((a > b)? a : b)

static char* config_datafile 		= "/usr/local/apache/logs/error_log";
static char* config_historyfile 	= "/var/log/munin/apache_qos_logs_pos";
static char* config_logfile 		= "/var/log/munin/apache_qos_logs_log";

static int   test_mode 			= 0;
static int   config_mode		= 0;
static int   all_data			= 0;

static void print_config();
static void parse_qosdata();
static int regmatch(const regmatch_t* matchdata,const char* str,char** matches,int maxmatch);
static void regfreematch(char** matches,int maxmatch);

int main(int argc, char** argv) {

  // check other attributes 
  int 	i;
  for(i=1;i<argc;i++) {
    if(strcmp(argv[i],"config") == 0)
      config_mode = 1;
    if(strcmp(argv[i],"test") == 0)
      test_mode = 1;
    if(strcmp(argv[i],"all") == 0)
      all_data = 1;
  } 
  
  config_mode? print_config() : parse_qosdata();

  return 0;
}

static void print_config() {
  printf("graph_category apache\n");
  printf("graph_title QoS Access Blocks\n");
  printf("graph_vlabel blocks per second\n");
  printf("graph_args --upper-limit 200 --rigid\n");
  printf("qosblockmaxip.label max ip rule\n");
  printf("qosblockmaxip.type GAUGE\n");
  printf("qosblockmaxip.draw LINE1\n");
  printf("qosblockspider.label robot limit\n");
  printf("qosblockspider.type GAUGE\n");
  printf("qosblockspider.draw LINE1\n");
  printf("qosblockbruteforce.label brute force\n");
  printf("qosblockbruteforce.type GAUGE\n");
  printf("qosblockbruteforce.draw LINE1\n");
  printf("qosblockdatarate.label data rate\n");
  printf("qosblockdatarate.type GAUGE\n");
  printf("qosblockdatarate.draw LINE1\n");
  printf("qosblockdynamic.label dynamic\n");
  printf("qosblockdynamic.type GAUGE\n");
  printf("qosblockdynamic.draw LINE1\n");
  printf("qosblock.label other\n");
  printf("qosblock.type GAUGE\n");
  printf("qosblock.draw LINE1\n");
}

static void parse_qosdata() {
  FILE*		log_file;
  FILE* 	data_file;
  FILE*		history_file;
  char 		entry[1024];

  int		result_maxip 		= 0;
  int		result_spider		= 0;
  int		result_bruteforce 	= 0;
  int		result_datarate		= 0;
  int		result_dynamic		= 0;
  int		result_other		= 0;
  int		count			= 0;

  const char*  	timestamp_r	 	= "^\\[([[:alnum:][:space:]:]*)\\]";
  regex_t       timestamp_rc;
  regmatch_t	timestamp_m[2];
  char*		timestamp_str[2];

  time_t	now;

  int		status;

  now = time(NULL);

  log_file = fopen(config_logfile,"a+");
  fprintf(log_file,"started at %s",ctime(&now));

  status = regcomp(&timestamp_rc,timestamp_r,REG_EXTENDED);  
  if(status) {
    char	errortext[128] = "";

    regerror(status,&timestamp_rc,errortext,sizeof(errortext));
    printf("error compiling regex: %s\n",errortext);
    exit(1);
  }

  data_file = fopen(config_datafile,"r");
  if(!data_file) {
    printf("unable to open data file\n");
    exit(1);
  }

  history_file = fopen(config_historyfile,"r+");
  if(history_file != NULL) {
    if(fgets(entry,sizeof(entry),history_file)) {
      int 		offset = atoi(entry);
      struct stat	finfo;
      
      status = fstat(fileno(data_file),&finfo);
      if(status == 0 && finfo.st_size >= offset && all_data == 0) {
	fseek(data_file,offset,SEEK_SET);
        fprintf(log_file,"skipping to log location %d\n",offset);
      } 
    }
  }  

  while(fgets(entry,sizeof(entry),data_file)) {
    struct tm	t;
    time_t	logtime;

    status = regexec(&timestamp_rc,entry,2,timestamp_m,0);
    if(status == REG_NOMATCH) {
      printf("unable to find timestamp via regex: '%s'\n",entry);
      printf("regex was: '%s'\n",timestamp_r);
      break;
    }
    regmatch(timestamp_m,entry,timestamp_str,2);

    // read timestamp and eval if line applies
    // [Thu Aug 06 13:12:01 2015]
    char		t_wday[4], t_mon[4];
    static const char*	l_mon[]  = { "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    memset(&t,0,sizeof(t));
    status = sscanf(timestamp_str[1],"%3s %3s %d %02d:%02d:%02d %04d",t_wday,t_mon,&t.tm_mday,&t.tm_hour,&t.tm_min,&t.tm_sec,&t.tm_year);
    t.tm_year -= 1900;
    for(t.tm_mon=0;t.tm_mon<12;t.tm_mon++) {
      if(strcmp(t_mon,l_mon[t.tm_mon]) == 0) 
	break;
    }
    logtime = mktime(&t);

    if(all_data == 1 || now - logtime <= 300){

      // must have 'qos' and 'access denied'
      if(strstr(entry,"mod_qos") == NULL)
	continue;
      if(strstr(entry,"access denied") == NULL)
	continue;

      if(strstr(entry,"QS_SrvMaxConnPerIP") != NULL) {
	result_maxip++;
      } else if(strstr(entry,"QS_CondLocRequestLimitMatch") != NULL) {
	result_spider++;
      } else if(strstr(entry,"QS_ClientEventBlockCount") != NULL) {
        result_bruteforce++;
      } else if(strstr(entry,"QS_SrvMinDataRate") != NULL) {
 	result_datarate++;
      } else if(strstr(entry,"QS_LocRequestLimit* rule") != NULL) {
        result_dynamic++;
      } else {
        result_other++;
      }

      count++;
    }
    
    regfreematch(timestamp_str,2);
  }

  fprintf(log_file,"... processed %d log entries from the last 5 minutes\n",count);

  if(!test_mode) {
    if(history_file != NULL) {
      fseek(history_file,0,SEEK_SET);
      fprintf(history_file,"%d",ftell(data_file));
      fclose(history_file);
    } else {
      history_file = fopen(config_historyfile,"w");
      if(history_file != NULL) {
        fprintf(history_file,"%d",ftell(data_file));
        fclose(history_file);
      }
    }
  }

  regfree(&timestamp_rc);
  fclose(data_file);
  fclose(log_file);

  printf("qosblockmaxip.value %d\n",result_maxip);
  printf("qosblockspider.value %d\n",result_spider);
  printf("qosblockbruteforce.value %d\n",result_bruteforce);
  printf("qosblockdatarate.value %d\n",result_datarate);
  printf("qosblockdynamic.value %d\n",result_dynamic);
  printf("qosblock.value %d\n",result_other);
}

static int regmatch(const regmatch_t* matchdata,const char* str,char** matches,int maxmatch) {
  int 	start;
  int	end;
  int	count;
  int 	i,n;

  for(i=0;i<maxmatch;i++) {
    if(matchdata[i].rm_so == -1)
      break;
    
    n = matchdata[i].rm_eo - matchdata[i].rm_so;
    matches[i] = malloc(n + 1);
    strncpy(matches[i],str+matchdata[i].rm_so,n);
    matches[i][n] = 0;
  }
  count = i;
  for(;i<maxmatch;i++)
    matches[i] = NULL;

  return(count);
}

static void regfreematch(char** matches,int maxmatch) {
  int	i;

  for(i=0;i<maxmatch;i++) {
    if(matches[i] != NULL)
      free(matches[i]);
  }
}

