/*
Exciting Licence Info.....

This file is part of FingerprinTLS.

FingerprinTLS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

FingerprinTLS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Foobar.  If not, see <http://www.gnu.org/licenses/>.

Exciting Licence Info Addendum.....

FingerprinTLS is additionally released under the "don't judge me" program
whereby it is forbidden to rip into me too harshly for programming
mistakes, kthnxbai.

*/

// TODO
// XXX Add UDP support (not as easy as I thought, DTLS has differences... still add it though)
// XXX enhance search to include sorting per list/thread/shard/thingy
// XXX add 6in4 support (should be as simple as UDP and IPv6... in theory)


#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip6.h>

/* For TimeStamping from pcap_pkthdr */
#include <time.h>

/* For the signal handler stuff */
#include <signal.h>

/* And my own signal handler functions */
#include "signal.c"

/* My own header sherbizzle */
#include "fingerprintls.h"

/* Pthread stuff */
#include <pthread.h>
#include "pthread.c"

/* Stuff to process packets */
#include "packet_processing.c"



/*
 * print help text
 */
void print_usage(char *bin_name) {
	fprintf(stderr, "Usage: %s <options>\n\n", bin_name);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "    -h                This message\n");
	fprintf(stderr, "    -i <interface>    Sniff packets from specified interface\n");
	fprintf(stderr, "    -p <pcap file>    Read packets from specified pcap file\n");
	fprintf(stderr, "    -j <json file>    Output JSON fingerprints\n");
	fprintf(stderr, "    -s                Output JSON signatures of unknown connections to stdout\n");
	fprintf(stderr, "    -d                Show reasons for discarded packets (post BPF)\n");
	fprintf(stderr, "    -f <fpdb>         Load the (binary) FingerPrint Database\n");
	fprintf(stderr, "    -u <uid>          Drop privileges to specified UID (not username)\n");
	fprintf(stderr, "\n");
	return;
}

/* Testing another way of searching the in memory database */
uint shard_fp (struct fingerprint_new *fp_lookup, uint16_t maxshard) {
				return (((fp_lookup->ciphersuite_length) + (fp_lookup->tls_version)) & (maxshard -1));
}

int main(int argc, char **argv) {

	char *dev = NULL;											/* capture device name */
	char *pcap_file = NULL;
	char *unpriv_user = NULL;							/* User for dropping privs */
	char errbuf[PCAP_ERRBUF_SIZE];				/* error buffer */
	extern pcap_t *handle;								/* packet capture handle */

	char *filter_exp = default_filter;
	int arg_start = 1, i;
	extern struct bpf_program fp;					/* compiled filter program (expression) */

	extern FILE *json_fd, *fpdb_fd;
	int filesize;
	uint8_t *fpdb_raw = NULL;
	int	fp_count = 0;
	extern int show_drops;
	extern char hostname[HOST_NAME_MAX];
	show_drops = 0;

	/* Threads */
	extern struct pthread_config *pthread_config_ptr;


	/* Make sure pipe sees new packets unbuffered. */
	setvbuf(stdout, (char *)NULL, _IOLBF, 0);

	if (argc == 1) {
		print_usage(argv[0]);
		exit(-1);
	}
	/* Do the -something switches  - yes this isn't very nice and doesn't support -abcd */
	for (i = arg_start; i < argc && argv[i][0] == '-' ; i++) {
		switch (argv[i][1]) {
			case '?':
			case 'h':
				print_usage(argv[0]);
				exit(0);
				break;
			case 'p':
				pcap_file = argv[++i];
				break;
			case 'i':
				dev = argv[++i];
				break;
			case 'j':
				/* JSON output to file */
				if((json_fd = fopen(argv[++i], "a")) == NULL) {
					printf("Cannot open JSON file for output\n");
					exit(-1);
				}
				setvbuf(json_fd, (char *)NULL, _IOLBF, 0);
				break;
			case 's':
				/* JSON output to stdout */
				if((json_fd = fopen("/dev/stdout", "a")) == NULL) {
					printf("Cannot open JSON file for output\n");
					exit(-1);
				}
				break;
			case 'd':
				/* Show Dropped Packet Info */
				show_drops = 1;
				break;
			case 'u':
				/* User for dropping privileges to */
				unpriv_user = argv[++i];
				break;
			case 'f':
				/* Read the *new* *sparkly* *probably broken* :) binary Fingerprint Database from file */
				/* In the future this will be to override the default location as this will be the default format */
				if((fpdb_fd = fopen(argv[++i], "r")) == NULL) {
					printf("Cannot open fingerprint database file\n");
					exit(-1);
				}
				break;
			default :
				printf("Unknown option '%s'\n", argv[i]);
				exit(-1);
				break;

		}
	}

	/*
		Fingerprint DB to load
		This needs to be before the priv drop in case the fingerprint db requires root privs to read.
	*/
	if(fpdb_fd == NULL) {
		/* No filename set, trying the current directory */
		if((fpdb_fd = fopen("tlsfp.db", "r")) == NULL) {
			printf("Cannot open fingerprint database file (try -f)\n");
			printf("(This is a new feature, tlsfp.db should be in the source code directory)\n");
			exit(-1);
		}
	}

	/*
		Checks required directly after switches are set
	*/
	if ((dev != NULL) && (pcap_file != NULL)) {
		printf("-p and -i are mutually exclusive\n");
		exit(-1);
	}

	/*
		setup hostname variable for use in logs (incase of multiple hosts)
		This is set so early incase first packet to first thread is unknown signature.
	*/
	extern char hostname[HOST_NAME_MAX];
	if(gethostname(hostname, HOST_NAME_MAX) != 0) {
		sprintf(hostname, "unknown");
	}

	/*
		Need something in place before the threads spin up
		XXX need to block them until FPDB loaded before this is commit'd
	*/
	int x, y;
	struct fingerprint_new *fp_current;
	extern struct fingerprint_new *search[8][4];

	/* Initialise so that we know when we are on the first in any one chain */
	for (x = 0 ; x < 8 ; x++) {
		for (y = 0 ; y < 4 ; y++) {
			search[x][y] = NULL;
			//pthread_mutex_init(&search[x][y]->fpdb_mutex, NULL);
		}
	}


	/*
		Setup a worker thread per "shard", and perform some per-thread activities
	*/
	struct pthread_config *working_pthread_config;
	extern struct pthread_config *next_thread_config;
	working_pthread_config = pthread_config_ptr = calloc(1, sizeof(struct pthread_config));
	long pt;

	/* Initialise the Mutexs before the threads start */
	extern pthread_mutex_t log_mutex;
	extern pthread_mutex_t json_mutex;
	extern pthread_mutex_t fpdb_mutex;
	pthread_mutex_init(&log_mutex, NULL);
	pthread_mutex_init(&json_mutex, NULL);
	pthread_mutex_init(&fpdb_mutex, NULL);

	for (i = 0; i < SHARDNUM ; i++) {
		working_pthread_config->threadnum = i;
		pthread_mutex_init(&working_pthread_config->thread_mutex, NULL);
		pthread_mutex_lock(&working_pthread_config->thread_mutex);

		/*
			Setup the pcap readeerererering stuff
		*/
		if(dev != NULL) {
			if (i == 0) {
				/*
					First thread will set the NIC into promisc mode
				*/
  			working_pthread_config->handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
			} else {
				/*
					other threads can just sniff without promisc thanks to thread 0
				*/
  			working_pthread_config->handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, errbuf);
			}

			if(working_pthread_config->handle == NULL) {
				printf("Error opening %s\n",dev);
				printf("'%s'\n",errbuf);
				return 0;
			} else {
				printf("Using interface: %s\n",dev);
			}
		}

		if (pcap_file != NULL) {
			working_pthread_config->handle = pcap_open_offline(pcap_file, errbuf);
			if(working_pthread_config->handle == NULL) {
				printf("Error opening %s\n",pcap_file);
				printf("'%s'\n",errbuf);
				return 0;
			} else {
				printf("Using pcapfile: %s\n",pcap_file);
			}
		}
		/* *********************************** */

		/*
			make sure we're capturing on an Ethernet device [2]
		*/
		if (pcap_datalink(working_pthread_config->handle) != DLT_EN10MB) {
			fprintf(stderr, "%s is not an Ethernet\n", dev);
			exit(EXIT_FAILURE);
		}

		/*
			compile the filter expression
			netmask is set to 0 because we don't care and it saves looking it up :)
		*/
		if (pcap_compile(working_pthread_config->handle, &fp, default_filter, 0, 0) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n",
					filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}

		/*
			apply the compiled filter
		*/
		pt = pthread_create(&working_pthread_config->thread_handle, NULL, packet_pthread, (void *)i);
		if (pcap_setfilter(working_pthread_config->handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n",
					filter_exp, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}

		/*
			Allocate the next thread config for the next loop around
		*/
		if(i < (SHARDNUM-1)) {
        working_pthread_config->next = calloc(1, sizeof(struct pthread_config));
        working_pthread_config = working_pthread_config->next;
		} else {
        working_pthread_config->next = pthread_config_ptr;
		}

	}

	/* Interface should already be opened, and files read we can drop privs now */
	/* This should stay the first action as lowering privs reduces risk from any subsequent actions */
	/* being poorly implimented and running as root */
	if (unpriv_user != NULL) {
		if (setgid(getgid()) == -1) {
  		fprintf(stderr, "WARNING: could not drop group privileges\n");
		} else {
			fprintf(stderr, "Dropped effective group successfully\n");
		}
		if (setuid(atoi(unpriv_user)) == -1) {
			fprintf(stderr, "WARNING: could not drop privileges to specified UID\n");
		} else {
			fprintf(stderr, "Changed UID successfully\n");
		}
	}


	/* XXX This if can go when this is "the way" */
	if(fpdb_fd != NULL) {
		/* Find the filesize (seek, tell, seekback) */
		fseek(fpdb_fd, 0L, SEEK_END);
		filesize = ftell(fpdb_fd);
		fseek(fpdb_fd, 0L, SEEK_SET);

		/* Allocate memory and store the file in fpdb_raw */
		fpdb_raw = malloc(filesize);
		if (fread(fpdb_raw, 1, filesize, fpdb_fd) == filesize) {
			// printf("Yay, looks like the FPDB file loaded ok\n");
			fclose(fpdb_fd);
		} else {
			printf("There seems to be a problem reading the FPDB file\n");
			fclose(fpdb_fd);
			exit(-1);
		}
	}

	/* Check and move past the version header (quit if it's wrong) */
	if (*fpdb_raw == 0) {
		fpdb_raw++;
	} else {
		printf("Unknown version of FPDB file\n");
		exit(-1);
	}



	/* Filesize -1 because of the header, loops through the file, one loop per fingerprint */
	for (x = 0 ; x < (filesize-1) ; fp_count++) {
		/* Allocating one my one instead of in a block, may revise this plan later */
		/* This will only save time on startup as opposed to during operation though */

		/* Allocate out the memory for the one signature */
		fp_current = malloc(sizeof(struct fingerprint_new));

		// XXX consider copied (i.e. length) values being free'd to save a little RAM here and there <-- future thing

		fp_current->fingerprint_id = (uint16_t) ((uint16_t)*(fpdb_raw+x) << 8) + ((uint8_t)*(fpdb_raw+x+1));
		x += 2;
		fp_current->desc_length =  (uint16_t) ((uint16_t)*(fpdb_raw+x) << 8) + ((uint8_t)*(fpdb_raw+x+1));
		fp_current->desc = (char *)fpdb_raw+x+2;

		x += (uint16_t) ((*(fpdb_raw+x) >> 16) + (*(fpdb_raw+x+1)) + 1); // Skip the description

		fp_current->record_tls_version = (uint16_t) ((uint16_t)*(fpdb_raw+x+1) << 8) + ((uint8_t)*(fpdb_raw+x+2));
		fp_current->tls_version = (uint16_t) ((uint16_t)*(fpdb_raw+x+3) << 8) + ((uint8_t)*(fpdb_raw+x+4));
		fp_current->ciphersuite_length = (uint16_t) ((uint16_t)*(fpdb_raw+x+5) << 8) + ((uint8_t)*(fpdb_raw+x+6));
		fp_current->ciphersuite = fpdb_raw+x+7;

		x += (uint16_t) ((*(fpdb_raw+x+5) >> 16) + (*(fpdb_raw+x+6)))+7; // Skip the ciphersuites

		fp_current->compression_length = *(fpdb_raw+x);
		fp_current->compression = fpdb_raw+x+1;

		x += (*(fpdb_raw+x))+1; // Skip over compression algo's

		fp_current->extensions_length = (uint16_t) ((uint16_t)*(fpdb_raw+x) << 8) + ((uint8_t)*(fpdb_raw+x+1));
		fp_current->extensions = fpdb_raw+x+2;

		x += (uint16_t)((*(fpdb_raw+x) >> 16) + *(fpdb_raw+x+1))+2; // Skip extensions list (not extensions - just the list)

		/* Lengths for the extensions which do not exist have already been set to 0 by fingerprintout.py */

		fp_current->curves_length = (uint16_t) ((uint16_t)*(fpdb_raw+x) << 8) + ((uint8_t)*(fpdb_raw+x+1));

		if(fp_current->curves_length == 0) {
			fp_current->curves = NULL;
		} else {
			fp_current->curves = fpdb_raw+x+2;
		}

		x += (uint16_t)((*(fpdb_raw+x) >> 16) + *(fpdb_raw+x+1))+2;  // Skip past curves

		fp_current->sig_alg_length = (uint16_t) ((uint16_t)*(fpdb_raw+x) << 8) + ((uint8_t)*(fpdb_raw+x+1));

		if(fp_current->sig_alg_length == 0) {
			fp_current->sig_alg = NULL;
		} else {
			fp_current->sig_alg = fpdb_raw+x+2;
		}

		x += (uint16_t)((*(fpdb_raw+x) >> 16) + *(fpdb_raw+x+1))+2;  // Skip past signature algorithms

		fp_current->ec_point_fmt_length = (uint16_t) ((uint16_t)*(fpdb_raw+x) << 8) + ((uint8_t)*(fpdb_raw+x+1));

		if(fp_current->ec_point_fmt_length == 0) {
			fp_current->ec_point_fmt = NULL;
		} else {
			fp_current->ec_point_fmt = fpdb_raw+x+2;
		}
		x += (uint16_t)((*(fpdb_raw+x) >> 16) + *(fpdb_raw+x+1))+2;

		/* Multi-array of pointers to appropriate (smaller) list */
		/* XXX This should still be ordered for faster search */
		fp_current->next = search[((fp_current->ciphersuite_length & 0x000F) >> 1 )][((fp_current->tls_version) & 0x00FF)];
		search[((fp_current->ciphersuite_length & 0x000F) >> 1 )][((fp_current->tls_version) & 0x00FF)] = fp_current;
	}

	printf("Loaded %i signatures\n", fp_count);


	// Register signal Handlers
	if(!(register_signals())) {
		printf("Could not register signal handlers\n");
		exit(0);
	}

	/* XXX HORRIBLE HORRIBLE KLUDGE TO AVOID if's everywhere.  I KNOW OK?! */
	if(json_fd == NULL) {
		if((json_fd = fopen("/dev/null", "a")) == NULL) {
			printf("Cannot open JSON file (/dev/null) for output\n");
			exit(-1);
		}
	}

	/*
		Unlock threads and let them run....
	*/
	working_pthread_config = pthread_config_ptr;
	for (i = 0; i < SHARDNUM ; working_pthread_config = working_pthread_config->next) {
		pthread_mutex_unlock(&working_pthread_config->thread_mutex);
	}

	// XXX Temp holder for threading fun
	while(1) {
		sleep(60);
	}

	fprintf(stderr, "Reached end of pcap\n");

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);



	return 0;
}
