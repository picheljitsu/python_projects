from datetime import datetime, timedelta

#sample link
#https://###OMITTED#####/app/kibana#/discover?_g=(refreshInterval:(display:Off,pause:!f,value:0),
#time:(from:'2017-06-30T22:18:00.000Z',mode:absolute,to:'2017-06-30T22:22:00.000Z'),
#timetime:(from:'2017-06-30T22:18:25.000Z',mode:absolute,to:'2017-06-30T22:22:25.000Z'))
#&_a=(columns:!(sourceAddress,destinationAddress,requestUrl,requestContext,eventOutcome),
#index:bluecoat,interval:auto,query:(query_string:(analyze_wildcard:!t,lowercase_expanded_terms:!f,query:'10.34.136.13%20AND%20198.177.10.236')),sort:!('@timestamp',desc))


local_timestamp = "2017/06/30 17:20:25"
src_host = "10.34.136.13"
dst_host = "198.177.10.236"
time_delta = 2
#Should be taken calculated from a timesource to account for timezone changes
zulu_diff = 5

def construct_link(local_timestamp,src_host,dst_host,zulu_diff,time_delta):
	local_timestamp = datetime.strptime(local_timestamp, "%Y/%m/%d %H:%M:%S") #Make timestamp object 
	zulu_timestamp = local_timestamp + timedelta(hours=zulu_diff) #Convert to Zulu first
	zulu_delta_before = ((zulu_timestamp - timedelta(minutes=time_delta)).strftime("%Y-%m-%d %H:%M:%S")).replace(' ','T') + ".000Z"	#Subtract delta and format
	zulu_delta_after = ((zulu_timestamp + timedelta(minutes=time_delta)).strftime("%Y-%m-%d %H:%M:%S")).replace(' ','T') + ".000Z"	#Add delta and format
	url = "https://###OMITTED#####/app/kibana#/discover?_g=(refreshInterval:(display:Off,pause:!f,value:0),"
	url += "time:(from:'%s',mode:absolute,to:'%s'))" % (zulu_delta_before,zulu_delta_after)
	url += "&_a=(columns:!(sourceAddress,destinationAddress,requestUrl,requestContext,eventOutcome),index:bluecoat,interval:auto,"
	url += "query:(query_string:(analyze_wildcard:!t,lowercase_expanded_terms:!f,query:'%s%%20AND%%20%s')),sort:!('@timestamp',desc))" % (src_host,dst_host)
	#print zulu_delta_before
	#print zulu_delta_after
	return url
	
print construct_link(local_timestamp,src_host,dst_host,zulu_diff,time_delta)



