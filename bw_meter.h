void batadv_bw_start(struct batadv_socket_client *socket_client,
		     struct batadv_icmp_packet *icmp_packet_bw);
void batadv_bw_stop(struct batadv_priv *bat_priv,
		    struct batadv_icmp_packet *icmp_packet);
void batadv_bw_meter_received(struct batadv_priv *bat_priv,
			      struct sk_buff *skb);
void batadv_bw_ack_received(struct batadv_priv *bat_priv, struct sk_buff *skb);
