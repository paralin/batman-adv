void batadv_bw_start(struct batadv_priv *bat_priv, struct icmp_packet_bw *ipb);
void batadv_bw_meter_received(struct batadv_priv *bat_priv,
			      struct sk_buff *skb);
void batadv_bw_ack_received(struct batadv_priv *bat_priv, struct sk_buff *skb);
int batadv_send_remaining_window(struct batadv_priv *bat_priv);
