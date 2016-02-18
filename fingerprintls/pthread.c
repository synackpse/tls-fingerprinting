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

void *packet_pthread(void *threadnum) {
        int counter;
        struct pthread_config *local_thread_config;
				extern struct pthread_config *pthread_config_ptr;

        /* Get "my" config (as opposed to other threads) before doing anything else */
        local_thread_config = pthread_config_ptr;
        for(counter = 0 ; counter < (int) threadnum ; counter++)
                local_thread_config = local_thread_config->next;

				/*
					Block until we get a lock on the mutex, this allows the main process to
					lock up a process until after setup is done.
				*/
				pthread_mutex_lock(&local_thread_config->thread_mutex);
				printf("Go\n");
				//pcap_loop(handle, -1, got_packet, NULL);
        pcap_loop(local_thread_config->handle, -1, got_packet, (u_char *)local_thread_config->threadnum);

				return 0;
}
