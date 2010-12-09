
void start_ndp_timer(struct batman_if *batman_if);
void stop_ndp_timer(struct batman_if *batman_if);

int ndp_init(struct batman_if *batman_if);
void ndp_free(struct batman_if *batman_if);

uint8_t ndp_fetch_tq(struct batman_packet_ndp *packet,
		 uint8_t *my_if_addr);
int ndp_update_neighbor(uint8_t my_tq, uint32_t seqno,
			struct batman_if *batman_if, uint8_t *neigh_addr);
