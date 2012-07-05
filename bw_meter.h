void batadv_bw_start(struct bat_priv *bat_priv, struct icmp_packet_bw *ipb);
void batadv_bw_meter_received(struct bat_priv *bat_priv, struct sk_buff *skb);
void batadv_bw_ack_received(struct bat_priv *bat_priv, struct sk_buff *skb);
int batadv_send_remaining_window(struct bat_priv *bat_priv,
				 struct bw_vars *bw_vars);
