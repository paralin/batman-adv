void batadv_bw_start(struct batadv_priv *bat_priv,
		     struct batadv_icmp_packet_bw *ipb);
void batadv_bw_meter_received(struct batadv_priv *bat_priv,
			      struct sk_buff *skb);
void batadv_bw_ack_received(struct batadv_priv *bat_priv, struct sk_buff *skb);
