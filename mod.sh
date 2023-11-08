

#!/usr/bin/env bash

function banner_graber(){
	source "${SCRIPTPATH}"/banners.txt
	randx=$(shuf -i 1-23 -n 1)
	tmp="banner${randx}" 
	banner_code=${!tmp}
	echo -e "${banner_code}"
}
function banner(){
	banner_code=$(banner_graber)
	printf "\n${bgreen}${banner_code}"
	printf "\n ${reconftw_version}                                 by @araselmir${reset}\n"
}

###############################################################################################################
############################################### SUBDOMAINS ####################################################
###############################################################################################################

function subdomains_full(){
	NUMOFLINES_subs="0"
	NUMOFLINES_probed="0"
	printf "${bgreen}#######################################################################\n\n"
	! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && printf "${bblue} Subdomain Enumeration $domain\n\n"
	[[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && printf "${bblue} Scanning IP $domain\n\n"
	[ -s "subdomains/subdomains.txt" ] && cp subdomains/subdomains.txt .tmp/subdomains_old.txt
	[ -s "webs/webs.txt" ] && cp webs/webs.txt .tmp/probed_old.txt

	if ( [ ! -f "$called_fn_dir/.sub_active" ] || [ ! -f "$called_fn_dir/.sub_brute" ] || [ ! -f "$called_fn_dir/.sub_permut" ] || [ ! -f "$called_fn_dir/.sub_recursive_brute" ] )  || [ "$DIFF" = true ] ; then
		resolvers_update
	fi

	[ -s "${inScope_file}" ] && cat ${inScope_file} | anew -q subdomains/subdomains.txt

	if ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]] && [ "$SUBDOMAINS_GENERAL" = true ]; then
		sub_passive
		sub_crt
		sub_active
		sub_noerror
		sub_brute
		sub_permut
		sub_regex_permut
		#sub_gpt
		sub_recursive_passive
		sub_recursive_brute
		sub_dns
		sub_scraping
		sub_analytics
	else 
		notification "IP/CIDR detected, subdomains search skipped" info
		echo $domain | anew -q subdomains/subdomains.txt
	fi

	webprobe_simple
	if [ -s "subdomains/subdomains.txt" ]; then
		[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file subdomains/subdomains.txt
		NUMOFLINES_subs=$(cat subdomains/subdomains.txt 2>>"$LOGFILE" | anew .tmp/subdomains_old.txt | sed '/^$/d' | wc -l)
	fi
	if [ -s "webs/webs.txt" ]; then
		[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file webs/webs.txt
		NUMOFLINES_probed=$(cat webs/webs.txt 2>>"$LOGFILE" | anew .tmp/probed_old.txt | sed '/^$/d' | wc -l)
	fi
	printf "${bblue}\n Total subdomains: ${reset}\n\n"
	notification "- ${NUMOFLINES_subs} alive" good
	[ -s "subdomains/subdomains.txt" ] && cat subdomains/subdomains.txt | sort
	notification "- ${NUMOFLINES_probed} new web probed" good
	[ -s "webs/webs.txt" ] && cat webs/webs.txt | sort
	notification "Subdomain Enumeration Finished" good
	printf "${bblue} Results are saved in $domain/subdomains/subdomains.txt and webs/webs.txt${reset}\n"
	printf "${bgreen}#######################################################################\n\n"
}

function sub_passive(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBPASSIVE" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Passive Subdomain Enumeration"

		[[ $RUNAMASS == true ]] && timeout -k 1m ${AMASS_ENUM_TIMEOUT} amass enum -passive -d $domain -config $AMASS_CONFIG -timeout $AMASS_ENUM_TIMEOUT -json .tmp/amass_json.json 2>>"$LOGFILE" &>/dev/null
		[ -s ".tmp/amass_json.json" ] && cat .tmp/amass_json.json | jq -r '.name' | anew -q .tmp/amass_psub.txt
		[[ $RUNSUBFINDER == true ]] && subfinder -all -d "$domain" -silent -o .tmp/subfinder_psub.txt 2>>"$LOGFILE" >/dev/null


		if [ -s "${GITHUB_TOKENS}" ]; then
			if [ "$DEEP" = true ]; then
				github-subdomains -d $domain -t $GITHUB_TOKENS -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
			else
				github-subdomains -d $domain -k -q -t $GITHUB_TOKENS -o .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
			fi
		fi
		if [ -s "${GITLAB_TOKENS}" ]; then
			gitlab-subdomains -d $domain -t $GITLAB_TOKENS > .tmp/gitlab_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
		fi
		if [ "$INSCOPE" = true ]; then
			check_inscope .tmp/amass_psub.txt 2>>"$LOGFILE" >/dev/null
			check_inscope .tmp/subfinder_psub.txt 2>>"$LOGFILE" >/dev/null
			check_inscope .tmp/github_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
			check_inscope .tmp/gitlab_subdomains_psub.txt 2>>"$LOGFILE" >/dev/null
		fi
		NUMOFLINES=$(find .tmp -type f -iname "*_psub.txt" -exec cat {} + | sed "s/*.//" | anew .tmp/passive_subs.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} new subs (passive)" ${FUNCNAME[0]}
	else
		if [ "$SUBPASSIVE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_crt(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBCRT" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Crtsh Subdomain Enumeration"
		crt -s -json -l ${CTR_LIMIT} $domain 2>>"$LOGFILE" | jq -r '.[].subdomain' 2>>"$LOGFILE" | sed -e "s/^\\*\\.//" | anew -q .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" >/dev/null
		[[ "$INSCOPE" = true ]] && check_inscope .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" >/dev/null
		NUMOFLINES=$(cat .tmp/crtsh_subs_tmp.txt 2>>"$LOGFILE" | sed 's/\*.//g' | anew .tmp/crtsh_subs.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} new subs (cert transparency)" ${FUNCNAME[0]}
	else
		if [ "$SUBCRT" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_active(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Active Subdomain Enumeration"
		find .tmp -type f -iname "*_subs.txt" -exec cat {} + | anew -q .tmp/subs_no_resolved.txt
		[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file .tmp/subs_no_resolved.txt
		if [ ! "$AXIOM" = true ]; then
			resolvers_update_quick_local
			[ -s ".tmp/subs_no_resolved.txt" ] && puredns resolve .tmp/subs_no_resolved.txt -w .tmp/subdomains_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			resolvers_update_quick_axiom
			[ -s ".tmp/subs_no_resolved.txt" ] && axiom-scan .tmp/subs_no_resolved.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subdomains_tmp.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		echo $domain | dnsx -retry 3 -silent -r $resolvers_trusted 2>>"$LOGFILE" | anew -q .tmp/subdomains_tmp.txt
		if [ "$DEEP" = true ]; then
			cat .tmp/subdomains_tmp.txt | tlsx -san -cn -silent -ro -c $TLSX_THREADS -p $TLS_PORTS | anew -q .tmp/subdomains_tmp.txt
		else
			cat .tmp/subdomains_tmp.txt | tlsx -san -cn -silent -ro -c $TLSX_THREADS | anew -q .tmp/subdomains_tmp.txt
		fi
		[[ "$INSCOPE" = true ]] && check_inscope .tmp/subdomains_tmp.txt 2>>"$LOGFILE" >/dev/null
		NUMOFLINES=$(cat .tmp/subdomains_tmp.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} subs DNS resolved from passive" ${FUNCNAME[0]}
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function sub_noerror(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBNOERROR" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Checking NOERROR DNS response"
		if [[ $(echo "${RANDOM}thistotallynotexist${RANDOM}.$domain" | dnsx -r $resolvers -rcode noerror,nxdomain -retry 3 -silent | cut -d' ' -f2) == "[NXDOMAIN]" ]]; then 
			resolvers_update_quick_local
			if [ "$DEEP" = true ]; then
				dnsx -d $domain -r $resolvers -silent -rcode noerror -w $subs_wordlist_big | cut -d' ' -f1 | anew -q .tmp/subs_noerror.txt 2>>"$LOGFILE" >/dev/null
			else
				dnsx -d $domain -r $resolvers -silent -rcode noerror -w $subs_wordlist | cut -d' ' -f1 | anew -q .tmp/subs_noerror.txt 2>>"$LOGFILE" >/dev/null
			fi
			[[ "$INSCOPE" = true ]] && check_inscope .tmp/subs_noerror.txt 2>>"$LOGFILE" >/dev/null
			NUMOFLINES=$(cat .tmp/subs_noerror.txt 2>>"$LOGFILE" | sed "s/*.//" | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
			end_subfunc "${NUMOFLINES} new subs (DNS noerror)" ${FUNCNAME[0]}
		else 
			printf "\n${yellow} Detected DNSSEC black lies, skipping this technique ${reset}\n" 
		fi
	else
		if [ "$SUBBRUTE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_dns(){
	if [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : DNS Subdomain Enumeration and PTR search"
		if [ ! "$AXIOM" = true ]; then
			[ -s "subdomains/subdomains.txt" ] && cat subdomains/subdomains.txt | dnsx -r $resolvers_trusted -a -aaaa -cname -ns -ptr -mx -soa -silent -retry 3 -json -o subdomains/subdomains_dnsregs.json 2>>"$LOGFILE" >/dev/null
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[], try .aaaa[], try .cname[], try .ns[], try .ptr[], try .mx[], try .soa[]' 2>/dev/null | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew -q .tmp/subdomains_dns.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[]' | sort -u | hakip2host | cut -d' ' -f 3 | unfurl -u domains | sed -e 's/*\.//' -e 's/\.$//' -e '/\./!d' | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew -q .tmp/subdomains_dns.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try "\(.host) - \(.a[])"' 2>/dev/null | sort -u -k2 | anew -q subdomains/subdomains_ips.txt
			resolvers_update_quick_local
			[ -s ".tmp/subdomains_dns.txt" ] && puredns resolve .tmp/subdomains_dns.txt -w .tmp/subdomains_dns_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			[ -s "subdomains/subdomains.txt" ] && axiom-scan subdomains/subdomains.txt -m dnsx -retry 3 -a -aaaa -cname -ns -ptr -mx -soa -json -o subdomains/subdomains_dnsregs.json $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[]' | sort -u | anew -q .tmp/subdomains_dns_a_records.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[]' | sort -u | hakip2host | cut -d' ' -f 3 | unfurl -u domains | sed -e 's/*\.//' -e 's/\.$//' -e '/\./!d' | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew -q .tmp/subdomains_dns.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try .a[], try .aaaa[], try .cname[], try .ns[], try .ptr[], try .mx[], try .soa[]' 2>/dev/null | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew -q .tmp/subdomains_dns.txt
			[ -s "subdomains/subdomains_dnsregs.json" ] && cat subdomains/subdomains_dnsregs.json | jq -r 'try "\(.host) - \(.a[])"' 2>/dev/null | sort -u -k2 | anew -q subdomains/subdomains_ips.txt
			resolvers_update_quick_axiom
			[ -s ".tmp/subdomains_dns.txt" ] && axiom-scan .tmp/subdomains_dns.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subdomains_dns_resolved.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		[[ "$INSCOPE" = true ]] && check_inscope .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" >/dev/null
		NUMOFLINES=$(cat .tmp/subdomains_dns_resolved.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} new subs (dns resolution)" ${FUNCNAME[0]}
	else
		printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
	fi
}

function sub_brute(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBBRUTE" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Bruteforce Subdomain Enumeration"
		if [ ! "$AXIOM" = true ]; then
			resolvers_update_quick_local
			if [ "$DEEP" = true ]; then
				puredns bruteforce $subs_wordlist_big $domain -w .tmp/subs_brute.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
			else
				puredns bruteforce $subs_wordlist $domain -w .tmp/subs_brute.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
			fi
			[ -s ".tmp/subs_brute.txt" ] && puredns resolve .tmp/subs_brute.txt -w .tmp/subs_brute_valid.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			resolvers_update_quick_axiom
			if [ "$DEEP" = true ]; then
				axiom-scan $subs_wordlist_big -m puredns-single $domain -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subs_brute.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			else
				axiom-scan $subs_wordlist -m puredns-single $domain -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subs_brute.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
			[ -s ".tmp/subs_brute.txt" ] && axiom-scan .tmp/subs_brute.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/subs_brute_valid.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		[[ "$INSCOPE" = true ]] && check_inscope .tmp/subs_brute_valid.txt 2>>"$LOGFILE" >/dev/null
		NUMOFLINES=$(cat .tmp/subs_brute_valid.txt 2>>"$LOGFILE" | sed "s/*.//" | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} new subs (bruteforce)" ${FUNCNAME[0]}
	else
		if [ "$SUBBRUTE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_scraping(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBSCRAPING" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Source code scraping subdomain search"
		touch .tmp/scrap_subs.txt
		if [ -s "$dir/subdomains/subdomains.txt" ]; then
			if [[ $(cat subdomains/subdomains.txt | wc -l) -le $DEEP_LIMIT ]] || [ "$DEEP" = true ] ; then
				if [ ! "$AXIOM" = true ]; then
					resolvers_update_quick_local
					cat subdomains/subdomains.txt | httpx -follow-host-redirects -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info1.txt 2>>"$LOGFILE" >/dev/null
					[ -s ".tmp/web_full_info1.txt" ] && cat .tmp/web_full_info1.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
					[ -s ".tmp/probed_tmp_scrap.txt" ] && cat .tmp/probed_tmp_scrap.txt | httpx -tls-grab -tls-probe -csp-probe -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info2.txt 2>>"$LOGFILE" >/dev/null
					[ -s ".tmp/web_full_info2.txt" ] && cat .tmp/web_full_info2.txt | jq -r 'try ."tls-grab"."dns_names"[],try .csp.domains[],try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | sort -u | httpx -silent | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt

					if [ "$DEEP" = true ]; then
						[ -s ".tmp/probed_tmp_scrap.txt" ] && katana -silent -list .tmp/probed_tmp_scrap.txt -jc -kf all -c $KATANA_THREADS -d 3 -fs rdn -o .tmp/katana.txt 2>>"$LOGFILE" >/dev/null
					else
						[ -s ".tmp/probed_tmp_scrap.txt" ] && katana -silent -list .tmp/probed_tmp_scrap.txt -jc -kf all -c $KATANA_THREADS -d 2 -fs rdn -o .tmp/katana.txt 2>>"$LOGFILE" >/dev/null
					fi
				else
					resolvers_update_quick_axiom
					axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects -random-agent -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info1.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					[ -s ".tmp/web_full_info1.txt" ] && cat .tmp/web_full_info1.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
					[ -s ".tmp/probed_tmp_scrap.txt" ] && axiom-scan .tmp/probed_tmp_scrap.txt -m httpx -tls-grab -tls-probe -csp-probe -random-agent -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info2.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					[ -s ".tmp/web_full_info2.txt" ] && cat .tmp/web_full_info2.txt | jq -r 'try ."tls-grab"."dns_names"[],try .csp.domains[],try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | sort -u | httpx -silent | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
					if [ "$DEEP" = true ]; then
						[ -s ".tmp/probed_tmp_scrap.txt" ] && axiom-scan .tmp/probed_tmp_scrap.txt -m katana -jc -kf all -d 3 -fs rdn -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					else
						[ -s ".tmp/probed_tmp_scrap.txt" ] && axiom-scan .tmp/probed_tmp_scrap.txt -m katana -jc -kf all -d 2 -fs rdn -o .tmp/katana.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					fi
				fi
				sed -i '/^.\{2048\}./d' .tmp/katana.txt
				[ -s ".tmp/katana.txt" ] && cat .tmp/katana.txt | unfurl -u domains 2>>"$LOGFILE" | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew -q .tmp/scrap_subs.txt
				[ -s ".tmp/scrap_subs.txt" ] && puredns resolve .tmp/scrap_subs.txt -w .tmp/scrap_subs_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
				if [ "$INSCOPE" = true ]; then
					check_inscope .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" >/dev/null
				fi
				NUMOFLINES=$(cat .tmp/scrap_subs_resolved.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | tee .tmp/diff_scrap.txt | sed '/^$/d' | wc -l)
				[ -s ".tmp/diff_scrap.txt" ] && cat .tmp/diff_scrap.txt | httpx -follow-host-redirects -random-agent -status-code -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -timeout $HTTPX_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info3.txt 2>>"$LOGFILE" >/dev/null
				[ -s ".tmp/web_full_info3.txt" ] && cat .tmp/web_full_info3.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | anew .tmp/probed_tmp_scrap.txt | unfurl -u domains 2>>"$LOGFILE" | anew -q .tmp/scrap_subs.txt
				cat .tmp/web_full_info1.txt .tmp/web_full_info2.txt .tmp/web_full_info3.txt 2>>"$LOGFILE" | jq -s 'try .' | jq 'try unique_by(.input)' | jq 'try .[]' 2>>"$LOGFILE" > .tmp/web_full_info.txt
				end_subfunc "${NUMOFLINES} new subs (code scraping)" ${FUNCNAME[0]}
			else
				end_subfunc "Skipping Subdomains Web Scraping: Too Many Subdomains" ${FUNCNAME[0]}
			fi
		else
			end_subfunc "No subdomains to search (code scraping)" ${FUNCNAME[0]}
		fi
	else
		if [ "$SUBSCRAPING" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_analytics(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBANALYTICS" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Analytics Subdomain Enumeration"
		if [ -s ".tmp/probed_tmp_scrap.txt" ]; then
			mkdir -p .tmp/output_analytics/
			analyticsrelationships -ch < .tmp/probed_tmp_scrap.txt >> .tmp/analytics_subs_tmp.txt 2>>"$LOGFILE"

			[ -s ".tmp/analytics_subs_tmp.txt" ] && cat .tmp/analytics_subs_tmp.txt | grep "\.$domain$\|^$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/|__ //" | anew -q .tmp/analytics_subs_clean.txt
			if [ ! "$AXIOM" = true ]; then
				resolvers_update_quick_local
				[ -s ".tmp/analytics_subs_clean.txt" ] && puredns resolve .tmp/analytics_subs_clean.txt -w .tmp/analytics_subs_resolved.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
			else
				resolvers_update_quick_axiom
				[ -s ".tmp/analytics_subs_clean.txt" ] && axiom-scan .tmp/analytics_subs_clean.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/analytics_subs_resolved.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
		fi
		[[ "$INSCOPE" = true ]] && check_inscope .tmp/analytics_subs_resolved.txt 2>>"$LOGFILE" >/dev/null
		NUMOFLINES=$(cat .tmp/analytics_subs_resolved.txt 2>>"$LOGFILE" | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		end_subfunc "${NUMOFLINES} new subs (analytics relationship)" ${FUNCNAME[0]}
	else
		if [ "$SUBANALYTICS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_permut(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBPERMUTE" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Permutations Subdomain Enumeration"
		if [ "$DEEP" = true ] || [ "$(cat subdomains/subdomains.txt | wc -l)" -le $DEEP_LIMIT ] ; then
			if [ "$PERMUTATIONS_OPTION" = "gotator" ] ; then
				[ -s "subdomains/subdomains.txt" ] && gotator -sub subdomains/subdomains.txt -perm $tools/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator1.txt
			else
				[ -s "subdomains/subdomains.txt" ] && ripgen -d subdomains/subdomains.txt -w $tools/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator1.txt
			fi
		elif [ "$(cat .tmp/subs_no_resolved.txt | wc -l)" -le $DEEP_LIMIT2 ]; then
			if [ "$PERMUTATIONS_OPTION" = "gotator" ] ; then
				[ -s ".tmp/subs_no_resolved.txt" ] && gotator -sub .tmp/subs_no_resolved.txt -perm $tools/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator1.txt
			else
				[ -s ".tmp/subs_no_resolved.txt" ] && ripgen -d .tmp/subs_no_resolved.txt -w $tools/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator1.txt
			fi
		else
			end_subfunc "Skipping Permutations: Too Many Subdomains" ${FUNCNAME[0]}
			return 1
		fi
		if [ ! "$AXIOM" = true ]; then
			resolvers_update_quick_local
			[ -s ".tmp/gotator1.txt" ] && puredns resolve .tmp/gotator1.txt -w .tmp/permute1.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			resolvers_update_quick_axiom
			[ -s ".tmp/gotator1.txt" ] && axiom-scan .tmp/gotator1.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/permute1.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		
		if [ "$PERMUTATIONS_OPTION" = "gotator" ] ; then
			[ -s ".tmp/permute1.txt" ] && gotator -sub .tmp/permute1.txt -perm $tools/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator2.txt
		else
			[ -s ".tmp/permute1.txt" ] && ripgen -d .tmp/permute1.txt -w $tools/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator2.txt
		fi

		if [ ! "$AXIOM" = true ]; then
			[ -s ".tmp/gotator2.txt" ] && puredns resolve .tmp/gotator2.txt -w .tmp/permute2.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			[ -s ".tmp/gotator2.txt" ] && axiom-scan .tmp/gotator2.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/permute2.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		cat .tmp/permute1.txt .tmp/permute2.txt 2>>"$LOGFILE" | anew -q .tmp/permute_subs.txt

		if [ -s ".tmp/permute_subs.txt" ]; then
			[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file .tmp/permute_subs.txt
			[[ "$INSCOPE" = true ]] && check_inscope .tmp/permute_subs.txt 2>>"$LOGFILE" >/dev/null
			NUMOFLINES=$(cat .tmp/permute_subs.txt 2>>"$LOGFILE" | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		else
			NUMOFLINES=0
		fi
		end_subfunc "${NUMOFLINES} new subs (permutations)" ${FUNCNAME[0]}
	else
		if [ "$SUBPERMUTE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_regex_permut(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBREGEXPERMUTE" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Permutations by regex analysis"
		cd "$tools/regulator" || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		python3 main.py -t $domain -f ${dir}/subdomains/subdomains.txt -o ${dir}/.tmp/${domain}.brute
		cd "$dir" || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }

		if [ ! "$AXIOM" = true ]; then
			resolvers_update_quick_local
			[ -s ".tmp/${domain}.brute" ] && puredns resolve .tmp/${domain}.brute -w .tmp/regulator.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			resolvers_update_quick_axiom
			[ -s ".tmp/${domain}.brute" ] && axiom-scan .tmp/${domain}.brute -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/regulator.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		
		if [ -s ".tmp/regulator.txt" ]; then
			[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file .tmp/regulator.txt
			[[ "$INSCOPE" = true ]] && check_inscope .tmp/regulator.txt 2>>"$LOGFILE" >/dev/null
			NUMOFLINES=$(cat .tmp/regulator.txt 2>>"$LOGFILE" | grep ".$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
		else
			NUMOFLINES=0
		fi
		end_subfunc "${NUMOFLINES} new subs (permutations by regex)" ${FUNCNAME[0]}
	else
		if [ "$SUBREGEXPERMUTE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_recursive_passive(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUB_RECURSIVE_PASSIVE" = true ] && [ -s "subdomains/subdomains.txt" ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Subdomains recursive search passive"
		# Passive recursive
		[ -s "subdomains/subdomains.txt" ] && dsieve -if subdomains/subdomains.txt -f 3 -top $DEEP_RECURSIVE_PASSIVE > .tmp/subdomains_recurs_top.txt
		if [ ! "$AXIOM" = true ]; then
			resolvers_update_quick_local
			[ -s ".tmp/subdomains_recurs_top.txt" ] && timeout -k 1m ${AMASS_ENUM_TIMEOUT}m amass enum -passive -df .tmp/subdomains_recurs_top.txt -nf subdomains/subdomains.txt -config $AMASS_CONFIG -timeout $AMASS_ENUM_TIMEOUT 2>>"$LOGFILE" | anew -q .tmp/passive_recursive.txt
			[ -s ".tmp/passive_recursive.txt" ] && puredns resolve .tmp/passive_recursive.txt -w .tmp/passive_recurs_tmp.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" &>/dev/null
		else
			resolvers_update_quick_axiom
			[ -s ".tmp/subdomains_recurs_top.txt" ] && axiom-scan .tmp/subdomains_recurs_top.txt -m amass -passive -o .tmp/amass_prec.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			[ -s ".tmp/amass_prec.txt" ] &&  cat .tmp/amass_prec.txt | anew -q .tmp/passive_recursive.txt
			[ -s ".tmp/passive_recursive.txt" ] && axiom-scan .tmp/passive_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/passive_recurs_tmp.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		[[ "$INSCOPE" = true ]] && check_inscope .tmp/passive_recurs_tmp.txt 2>>"$LOGFILE" >/dev/null
		NUMOFLINES=$(cat .tmp/passive_recurs_tmp.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed '/^$/d' | anew subdomains/subdomains.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (recursive)" ${FUNCNAME[0]}
	else
		if [ "$SUB_RECURSIVE_PASSIVE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function sub_recursive_brute(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUB_RECURSIVE_BRUTE" = true ] && [ -s "subdomains/subdomains.txt" ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Subdomains recursive search active"
		if [[ $(cat subdomains/subdomains.txt | wc -l) -le $DEEP_LIMIT ]] ; then
			[ ! -s ".tmp/subdomains_recurs_top.txt" ] && dsieve -if subdomains/subdomains.txt -f 3 -top $DEEP_RECURSIVE_PASSIVE > .tmp/subdomains_recurs_top.txt
			ripgen -d .tmp/subdomains_recurs_top.txt -w $subs_wordlist > .tmp/brute_recursive_wordlist.txt
			if [ ! "$AXIOM" = true ]; then
				resolvers_update_quick_local
				[ -s ".tmp/brute_recursive_wordlist.txt" ] && puredns resolve .tmp/brute_recursive_wordlist.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -w .tmp/brute_recursive_result.txt 2>>"$LOGFILE" >/dev/null
			else
				resolvers_update_quick_axiom
				[ -s ".tmp/brute_recursive_wordlist.txt" ] && axiom-scan .tmp/brute_recursive_wordlist.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/brute_recursive_result.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
			[ -s ".tmp/brute_recursive_result.txt" ] && cat .tmp/brute_recursive_result.txt | anew -q .tmp/brute_recursive.txt

			if [ "$PERMUTATIONS_OPTION" = "gotator" ] ; then
				[ -s ".tmp/brute_recursive.txt" ] && gotator -sub .tmp/brute_recursive.txt -perm $tools/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator1_recursive.txt
			else
				[ -s ".tmp/brute_recursive.txt" ] && ripgen -d .tmp/brute_recursive.txt -w $tools/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator1_recursive.txt
			fi
			
			if [ ! "$AXIOM" = true ]; then
				[ -s ".tmp/gotator1_recursive.txt" ] && puredns resolve .tmp/gotator1_recursive.txt -w .tmp/permute1_recursive.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
			else
				[ -s ".tmp/gotator1_recursive.txt" ] && axiom-scan .tmp/gotator1_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/permute1_recursive.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi

			if [ "$PERMUTATIONS_OPTION" = "gotator" ] ; then
				[ -s ".tmp/permute1_recursive.txt" ] && gotator -sub .tmp/permute1_recursive.txt -perm $tools/permutations_list.txt $GOTATOR_FLAGS -silent 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator2_recursive.txt
			else
				[ -s ".tmp/permute1_recursive.txt" ] && ripgen -d .tmp/permute1_recursive.txt -w $tools/permutations_list.txt 2>>"$LOGFILE" | head -c $PERMUTATIONS_LIMIT > .tmp/gotator2_recursive.txt
			fi
			
			if [ ! "$AXIOM" = true ]; then
			[ -s ".tmp/gotator2_recursive.txt" ] && puredns resolve .tmp/gotator2_recursive.txt -w .tmp/permute2_recursive.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT  --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
			else
				[ -s ".tmp/gotator2_recursive.txt" ] && axiom-scan .tmp/gotator2_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/permute2_recursive.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			fi
			cat .tmp/permute1_recursive.txt .tmp/permute2_recursive.txt 2>>"$LOGFILE" | anew -q .tmp/permute_recursive.txt
		else
			end_subfunc "skipped in this mode or defined in reconftw.cfg" ${FUNCNAME[0]}
		fi
		if [ "$INSCOPE" = true ]; then
			check_inscope .tmp/permute_recursive.txt 2>>"$LOGFILE" >/dev/null
			check_inscope .tmp/brute_recursive.txt 2>>"$LOGFILE" >/dev/null
		fi

		# Last validation
		cat .tmp/permute_recursive.txt .tmp/brute_recursive.txt 2>>"$LOGFILE" | anew -q .tmp/brute_perm_recursive.txt
		if [ ! "$AXIOM" = true ]; then
			[ -s ".tmp/brute_recursive.txt" ] && puredns resolve .tmp/brute_perm_recursive.txt -w .tmp/brute_perm_recursive_final.txt -r $resolvers --resolvers-trusted $resolvers_trusted -l $PUREDNS_PUBLIC_LIMIT --rate-limit-trusted $PUREDNS_TRUSTED_LIMIT --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT 2>>"$LOGFILE" >/dev/null
		else
			[ -s ".tmp/brute_recursive.txt" ] && axiom-scan .tmp/brute_perm_recursive.txt -m puredns-resolve -r /home/op/lists/resolvers.txt --resolvers-trusted /home/op/lists/resolvers_trusted.txt --wildcard-tests $PUREDNS_WILDCARDTEST_LIMIT --wildcard-batch $PUREDNS_WILDCARDBATCH_LIMIT -o .tmp/brute_perm_recursive_final.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi

		NUMOFLINES=$(cat .tmp/brute_perm_recursive_final.txt 2>>"$LOGFILE" | grep "\.$domain$\|^$domain$" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed '/^$/d' | anew subdomains/subdomains.txt | wc -l)
		end_subfunc "${NUMOFLINES} new subs (recursive active)" ${FUNCNAME[0]}
	else
		if [ "$SUB_RECURSIVE_BRUTE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function subtakeover(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$SUBTAKEOVER" = true ]; then
		start_func ${FUNCNAME[0]} "Looking for possible subdomain and DNS takeover"
		touch .tmp/tko.txt
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ ! "$AXIOM" = true ]; then
			nuclei -update 2>>"$LOGFILE" >/dev/null
			cat subdomains/subdomains.txt .tmp/webs_all.txt 2>/dev/null | nuclei -silent -nh -tags takeover -severity info,low,medium,high,critical -retries 3 -rl $NUCLEI_RATELIMIT -t ${NUCLEI_TEMPLATES_PATH} -o .tmp/tko.txt
		else
			cat subdomains/subdomains.txt .tmp/webs_all.txt 2>>"$LOGFILE" | sed '/^$/d' | anew -q .tmp/webs_subs.txt
			[ -s ".tmp/webs_subs.txt" ] && axiom-scan .tmp/webs_subs.txt -m nuclei --nuclei-templates ${NUCLEI_TEMPLATES_PATH} -tags takeover -nh -severity info,low,medium,high,critical -retries 3 -rl $NUCLEI_RATELIMIT -t ${NUCLEI_TEMPLATES_PATH} -o .tmp/tko.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi

		# DNS_TAKEOVER
		cat .tmp/subs_no_resolved.txt .tmp/subdomains_dns.txt .tmp/scrap_subs.txt .tmp/analytics_subs_clean.txt .tmp/passive_recursive.txt 2>/dev/null | anew -q .tmp/subs_dns_tko.txt
		cat .tmp/subs_dns_tko.txt 2>/dev/null | dnstake -c $DNSTAKE_THREADS -s 2>>"$LOGFILE" | sed '/^$/d' | anew -q .tmp/tko.txt

		sed -i '/^$/d' .tmp/tko.txt

		NUMOFLINES=$(cat .tmp/tko.txt 2>>"$LOGFILE" | anew webs/takeover.txt | sed '/^$/d' | wc -l)
		if [ "$NUMOFLINES" -gt 0 ]; then
			notification "${NUMOFLINES} new possible takeovers found" info
		fi
		end_func "Results are saved in $domain/webs/takeover.txt" ${FUNCNAME[0]}
	else
		if [ "$SUBTAKEOVER" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function zonetransfer(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$ZONETRANSFER" = true ] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "Zone transfer check"
		for ns in $(dig +short ns "$domain"); do dig axfr "$domain" @"$ns" >> subdomains/zonetransfer.txt; done
		if [ -s "subdomains/zonetransfer.txt" ]; then
			if ! grep -q "Transfer failed" subdomains/zonetransfer.txt ; then notification "Zone transfer found on ${domain}!" info; fi
		fi
		end_func "Results are saved in $domain/subdomains/zonetransfer.txt" ${FUNCNAME[0]}
	else
		if [ "$ZONETRANSFER" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [ "$ZONETRANSFER" = false ]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi
}

function s3buckets(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$S3BUCKETS" = true ] && ! [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
		start_func ${FUNCNAME[0]} "AWS S3 buckets search"
		# S3Scanner
		if [ ! "$AXIOM" = true ]; then
			[ -s "subdomains/subdomains.txt" ] && s3scanner scan -f subdomains/subdomains.txt 2>>"$LOGFILE" | anew -q .tmp/s3buckets.txt
		else
			axiom-scan subdomains/subdomains.txt -m s3scanner -o .tmp/s3buckets_tmp.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
			[ -s ".tmp/s3buckets_tmp.txt" ] && cat .tmp/s3buckets_tmp.txt .tmp/s3buckets_tmp2.txt 2>>"$LOGFILE" | anew -q .tmp/s3buckets.txt && sed -i '/^$/d' .tmp/s3buckets.txt
		fi
		# Cloudenum
		keyword=${domain%%.*}
		python3 ~/Tools/cloud_enum/cloud_enum.py -k $keyword -qs -l .tmp/output_cloud.txt 2>>"$LOGFILE" >/dev/null

		NUMOFLINES1=$(cat .tmp/output_cloud.txt 2>>"$LOGFILE" | sed '/^#/d' | sed '/^$/d' | anew subdomains/cloud_assets.txt | wc -l)
		if [ "$NUMOFLINES1" -gt 0 ]; then
			notification "${NUMOFLINES1} new cloud assets found" info
		fi
		NUMOFLINES2=$(cat .tmp/s3buckets.txt 2>>"$LOGFILE" | grep -aiv "not_exist" | grep -aiv "Warning:" | grep -aiv "invalid_name" | grep -aiv "^http" | awk 'NF' | anew subdomains/s3buckets.txt | sed '/^$/d' | wc -l)
		if [ "$NUMOFLINES2" -gt 0 ]; then
			notification "${NUMOFLINES2} new S3 buckets found" info
		fi

		end_func "Results are saved in subdomains/s3buckets.txt and subdomains/cloud_assets.txt" ${FUNCNAME[0]}
	else
		if [ "$S3BUCKETS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		elif [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then
			return
		else
			if [ "$S3BUCKETS" = false ]; then
				printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
			else
				printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
			fi
		fi
	fi
}

###############################################################################################################
########################################### WEB DETECTION #####################################################
###############################################################################################################

function webprobe_simple(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WEBPROBESIMPLE" = true ]; then
		start_subfunc ${FUNCNAME[0]} "Running : Http probing $domain"
		if [ ! "$AXIOM" = true ]; then
			cat subdomains/subdomains.txt | httpx ${HTTPX_FLAGS} -no-color -json -random-agent -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -retries 2 -timeout $HTTPX_TIMEOUT -o .tmp/web_full_info_probe.txt 2>>"$LOGFILE" >/dev/null
		else
			axiom-scan subdomains/subdomains.txt -m httpx ${HTTPX_FLAGS} -no-color -json -random-agent -threads $HTTPX_THREADS -rl $HTTPX_RATELIMIT -retries 2 -timeout $HTTPX_TIMEOUT -o .tmp/web_full_info_probe.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
		fi
		cat .tmp/web_full_info.txt .tmp/web_full_info_probe.txt webs/web_full_info.txt 2>>"$LOGFILE" | jq -s 'try .' | jq 'try unique_by(.input)' | jq 'try .[]' 2>>"$LOGFILE" > webs/web_full_info.txt
		[ -s "webs/web_full_info.txt" ] && cat webs/web_full_info.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | anew -q .tmp/probed_tmp.txt
		[ -s "webs/web_full_info.txt" ] && cat webs/web_full_info.txt | jq -r 'try . |"\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' | grep "$domain" | anew -q webs/web_full_info_plain.txt
		[ -s "$outOfScope_file" ] && deleteOutScoped $outOfScope_file .tmp/probed_tmp.txt
		NUMOFLINES=$(cat .tmp/probed_tmp.txt 2>>"$LOGFILE" | anew webs/webs.txt | sed '/^$/d' | wc -l)
		cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		end_subfunc "${NUMOFLINES} new websites resolved" ${FUNCNAME[0]}
		if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/webs.txt| wc -l) -le $DEEP_LIMIT2 ]]; then
			notification "Sending websites to proxy" info
			ffuf -mc all -w webs/webs.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" >/dev/null
		fi
	else
		if [ "$WEBPROBESIMPLE" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

function webprobe_full(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$WEBPROBEFULL" = true ]; then
		start_func ${FUNCNAME[0]} "Http probing non standard ports"
		if [ -s "subdomains/subdomains.txt" ]; then
			if [ ! "$AXIOM" = true ]; then
				if [ -s "subdomains/subdomains.txt" ]; then
					cat subdomains/subdomains.txt | httpx -follow-host-redirects -random-agent -status-code -p $UNCOMMON_PORTS_WEB -threads $HTTPX_UNCOMMONPORTS_THREADS -timeout $HTTPX_UNCOMMONPORTS_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" >/dev/null
				fi
			else
				if [ -s "subdomains/subdomains.txt" ]; then
					axiom-scan subdomains/subdomains.txt -m httpx -follow-host-redirects -H \"${HEADER}\" -status-code -p $UNCOMMON_PORTS_WEB -threads $HTTPX_UNCOMMONPORTS_THREADS -timeout $HTTPX_UNCOMMONPORTS_TIMEOUT -silent -retries 2 -title -web-server -tech-detect -location -no-color -json -o .tmp/web_full_info_uncommon.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
				fi
			fi
		fi
		[ -s ".tmp/web_full_info_uncommon.txt" ] && cat .tmp/web_full_info_uncommon.txt | jq -r 'try .url' 2>/dev/null | grep "$domain" | grep -E '^((http|https):\/\/)?([a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{1,}(\/.*)?$' | sed "s/*.//" | anew -q .tmp/probed_uncommon_ports_tmp.txt
		[ -s ".tmp/web_full_info_uncommon.txt" ] && cat .tmp/web_full_info_uncommon.txt | jq -r 'try . |"\(.url) [\(.status_code)] [\(.title)] [\(.webserver)] \(.tech)"' | anew -q webs/web_full_info_uncommon_plain.txt
		if [ -s ".tmp/web_full_info_uncommon.txt" ]; then
			if [[ $domain =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9] ]]; then 
				cat .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" | anew -q webs/web_full_info_uncommon.txt
			else
				cat .tmp/web_full_info_uncommon.txt 2>>"$LOGFILE" | grep "$domain" | anew -q webs/web_full_info_uncommon.txt
			fi
		fi
		NUMOFLINES=$(cat .tmp/probed_uncommon_ports_tmp.txt 2>>"$LOGFILE" | anew webs/webs_uncommon_ports.txt | sed '/^$/d' | wc -l)
		notification "Uncommon web ports: ${NUMOFLINES} new websites" good
		[ -s "webs/webs_uncommon_ports.txt" ] && cat webs/webs_uncommon_ports.txt
		cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		end_func "Results are saved in $domain/webs/webs_uncommon_ports.txt" ${FUNCNAME[0]}
		if [ "$PROXY" = true ] && [ -n "$proxy_url" ] && [[ $(cat webs/webs_uncommon_ports.txt| wc -l) -le $DEEP_LIMIT2 ]]; then
			notification "Sending websites with uncommon ports to proxy" info
			ffuf -mc all -w webs/webs_uncommon_ports.txt -u FUZZ -replay-proxy $proxy_url 2>>"$LOGFILE" >/dev/null
		fi
	else
		if [ "$WEBPROBEFULL" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}


function virtualhosts(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$VIRTUALHOSTS" = true ]; then
		start_func ${FUNCNAME[0]} "Virtual Hosts dicovery"
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		if [ -s ".tmp/webs_all.txt" ]; then
			mkdir -p $dir/virtualhosts $dir/.tmp/virtualhosts
			interlace -tL .tmp/webs_all.txt -threads ${INTERLACE_THREADS} -c "ffuf -ac -t ${FFUF_THREADS} -rate ${FFUF_RATELIMIT} -H \"${HEADER}\" -H \"Host: FUZZ._cleantarget_\" -w ${fuzz_wordlist} -maxtime ${FFUF_MAXTIME} -u  _target_ -of json -o _output_/_cleantarget_.json" -o $dir/.tmp/virtualhosts 2>>"$LOGFILE" >/dev/null
			for sub in $(cat .tmp/webs_all.txt); do
				sub_out=$(echo $sub | sed -e 's|^[^/]*//||' -e 's|/.*$||')
				[ -s "$dir/.tmp/virtualhosts/${sub_out}.json" ] && cat $dir/.tmp/virtualhosts/${sub_out}.json | jq -r 'try .results[] | "\(.status) \(.length) \(.url)"' | sort | anew -q $dir/virtualhosts/${sub_out}.txt
			done
			find $dir/virtualhosts/ -type f -iname "*.txt" -exec cat {} + 2>>"$LOGFILE" | anew -q $dir/virtualhosts/virtualhosts_full.txt
			end_func "Results are saved in $domain/virtualhosts/*subdomain*.txt" ${FUNCNAME[0]}
		else
			end_func "No $domain/web/webs.txts file found, virtualhosts skipped " ${FUNCNAME[0]}
		fi
	else
		if [ "$VIRTUALHOSTS" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

###############################################################################################################
############################################# WEB SCAN ########################################################
###############################################################################################################

function nuclei_check(){
	if { [ ! -f "$called_fn_dir/.${FUNCNAME[0]}" ] || [ "$DIFF" = true ]; } && [ "$NUCLEICHECK" = true ]; then
		start_func ${FUNCNAME[0]} "Templates based web scanner"
		nuclei -update 2>>"$LOGFILE" >/dev/null
		mkdir -p nuclei_output
		[ ! -s ".tmp/webs_all.txt" ] && cat webs/webs.txt webs/webs_uncommon_ports.txt 2>/dev/null | anew -q .tmp/webs_all.txt
		[ ! -s ".tmp/webs_subs.txt" ] && cat subdomains/subdomains.txt .tmp/webs_all.txt 2>>"$LOGFILE" | anew -q .tmp/webs_subs.txt
		if [ ! "$AXIOM" = true ]; then                 # avoid globbing (expansion of *).
			IFS=',' read -ra severity_array <<< "$NUCLEI_SEVERITY"
			for crit in "${severity_array[@]}"
			do
				printf "${yellow}\n Running : Nuclei $crit ${reset}\n\n"
				cat .tmp/webs_subs.txt 2>/dev/null | nuclei $NUCLEI_FLAGS -severity $crit -nh -rl $NUCLEI_RATELIMIT -o nuclei_output/${crit}.txt
			done
			printf "\n\n"
		else
			if [ -s ".tmp/webs_subs.txt" ]; then
				IFS=',' read -ra severity_array <<< "$NUCLEI_SEVERITY"
				for crit in "${severity_array[@]}"
				do
					printf "${yellow}\n Running : Nuclei $crit, check results on nuclei_output folder${reset}\n\n"
					axiom-scan .tmp/webs_subs.txt -m nuclei --nuclei-templates ${NUCLEI_TEMPLATES_PATH} -severity ${crit} -nh -rl $NUCLEI_RATELIMIT -o nuclei_output/${crit}.txt $AXIOM_EXTRA_ARGS 2>>"$LOGFILE" >/dev/null
					[ -s "nuclei_output/${crit}.txt" ] && cat nuclei_output/${crit}.txt
				done
				printf "\n\n"
			fi
		fi
		end_func "Results are saved in $domain/nuclei_output folder" ${FUNCNAME[0]}
	else
		if [ "$NUCLEICHECK" = false ]; then
			printf "\n${yellow} ${FUNCNAME[0]} skipped in this mode or defined in reconftw.cfg ${reset}\n"
		else
			printf "${yellow} ${FUNCNAME[0]} is already processed, to force executing ${FUNCNAME[0]} delete\n    $called_fn_dir/.${FUNCNAME[0]} ${reset}\n\n"
		fi
	fi
}

###############################################################################################################
######################################### VULNERABILITIES #####################################################
###############################################################################################################


###############################################################################################################
########################################## OPTIONS & MGMT #####################################################
###############################################################################################################

function deleteOutScoped(){
	if [ -s "$1" ]; then
		cat $1 | while read outscoped
		do
			if grep -q "^[*]" <<< $outscoped
			then
				outscoped="${outscoped:1}"
				sed -i /"$outscoped$"/d $2
			else
				sed -i /$outscoped/d $2
			fi
		done
	fi
}

function getElapsedTime {
	runtime=""
	local T=$2-$1
	local D=$((T/60/60/24))
	local H=$((T/60/60%24))
	local M=$((T/60%60))
	local S=$((T%60))
	(( $D > 0 )) && runtime="$runtime$D days, "
	(( $H > 0 )) && runtime="$runtime$H hours, "
	(( $M > 0 )) && runtime="$runtime$M minutes, "
	runtime="$runtime$S seconds."
}

function zipSnedOutputFolder {
	zip_name1=$(date +"%Y_%m_%d-%H.%M.%S")
	zip_name="${zip_name1}_${domain}.zip" 2>>"$LOGFILE" >/dev/null
	(cd "$dir" && zip -r "$zip_name" .)

	echo "Sending zip file "${dir}/${zip_name}""
	if [ -s "${dir}/$zip_name" ]; then
		sendToNotify "$dir/$zip_name"
		rm -f "${dir}/$zip_name"
	else
		notification "No Zip file to send" warn
	fi
}

function isAsciiText {
	IS_ASCII="False";
	if [[ $(file $1 | grep -o 'ASCII text$') == "ASCII text" ]]; then
		IS_ASCII="True";
	else
		IS_ASCII="False";
	fi
}

function output(){
	mkdir -p $dir_output
	cp -r $dir $dir_output
	[[ "$(dirname $dir)" != "$dir_output" ]] && rm -rf "$dir"
}

function remove_big_files(){
	eval rm -rf .tmp/gotator*.txt 2>>"$LOGFILE"
	eval rm -rf .tmp/brute_recursive_wordlist.txt 2>>"$LOGFILE"
	eval rm -rf .tmp/subs_dns_tko.txt  2>>"$LOGFILE"
	eval rm -rf .tmp/subs_no_resolved.txt .tmp/subdomains_dns.txt .tmp/brute_dns_tko.txt .tmp/scrap_subs.txt .tmp/analytics_subs_clean.txt .tmp/gotator1.txt .tmp/gotator2.txt .tmp/passive_recursive.txt .tmp/brute_recursive_wordlist.txt .tmp/gotator1_recursive.txt .tmp/gotator2_recursive.txt 2>>"$LOGFILE"
	eval find .tmp -type f -size +200M -exec rm -f {} + 2>>"$LOGFILE"
}

function notification(){
	if [ -n "$1" ] && [ -n "$2" ]; then
		case $2 in
			info)
				text="\n${bblue} ${1} ${reset}"
				printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
			warn)
				text="\n${yellow} ${1} ${reset}"
				printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
			error)
				text="\n${bred} ${1} ${reset}"
				printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
			good)
				text="\n${bgreen} ${1} ${reset}"
				printf "${text}\n" && printf "${text} - ${domain}\n" | $NOTIFY
			;;
		esac
	fi
}

function transfer { 
	if [ $# -eq 0 ]; then 
		echo "No arguments specified.\nUsage:\n transfer <file|directory>\n ... | transfer <file_name>">&2
		return 1
	fi
	if tty -s; then 
		file="$1"
		file_name=$(basename "$file")
		if [ ! -e "$file" ]; then 
			echo "$file: No such file or directory">&2
			return 1
		fi
		if [ -d "$file" ]; then
			file_name="$file_name.zip"
			(cd "$file"&&zip -r -q - .) | curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null
		else 
			cat "$file" | curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null
		fi
	else
		file_name=$1
		curl --progress-bar --upload-file "-" "https://transfer.sh/$file_name" | tee /dev/null
	fi
}

function sendToNotify {
	if [[ -z "$1" ]]; then
		printf "\n${yellow} no file provided to send ${reset}\n"
	else
		if [[ -z "$NOTIFY_CONFIG" ]]; then
			NOTIFY_CONFIG=~/.config/notify/provider-config.yaml
		fi
		if [ -n "$(find "${1}" -prune -size +8000000c)" ]; then
    		printf '%s is larger than 8MB, sending over transfer.sh\n' "${1}"
			transfer "${1}" | notify
			return 0
		fi
		if grep -q '^ telegram\|^telegram\|^    telegram' $NOTIFY_CONFIG ; then
			notification "Sending ${domain} data over Telegram" info
			telegram_chat_id=$(cat ${NOTIFY_CONFIG} | grep '^    telegram_chat_id\|^telegram_chat_id\|^    telegram_chat_id' | xargs | cut -d' ' -f2)
			telegram_key=$(cat ${NOTIFY_CONFIG} | grep '^    telegram_api_key\|^telegram_api_key\|^    telegram_apikey' | xargs | cut -d' ' -f2 )
			curl -F document=@${1} "https://api.telegram.org/bot${telegram_key}/sendDocument?chat_id=${telegram_chat_id}" 2>>"$LOGFILE" >/dev/null
		fi
		if grep -q '^ discord\|^discord\|^    discord' $NOTIFY_CONFIG ; then
			notification "Sending ${domain} data over Discord" info
			discord_url=$(cat ${NOTIFY_CONFIG} | grep '^ discord_webhook_url\|^discord_webhook_url\|^    discord_webhook_url' | xargs | cut -d' ' -f2)
			curl -v -i -H "Accept: application/json" -H "Content-Type: multipart/form-data" -X POST -F file1=@${1} $discord_url 2>>"$LOGFILE" >/dev/null
		fi
		if [[ -n "$slack_channel" ]] && [[ -n "$slack_auth" ]]; then
			notification "Sending ${domain} data over Slack" info
			curl -F file=@${1} -F "initial_comment=reconftw zip file" -F channels=${slack_channel} -H "Authorization: Bearer ${slack_auth}" https://slack.com/api/files.upload 2>>"$LOGFILE" >/dev/null
		fi
	fi
}

function start_func(){
	printf "${bgreen}#######################################################################"
	notification "${2}" info
	echo "[ $(date +"%F %T") ] Start function : ${1} " >> "${LOGFILE}"
	start=$(date +%s)
}

function end_func(){
	touch $called_fn_dir/.${2}
	end=$(date +%s)
	getElapsedTime $start $end
	notification "${2} Finished in ${runtime}" info
	echo "[ $(date +"%F %T") ] End function : ${2} " >> "${LOGFILE}"
	printf "${bblue} ${1} ${reset}\n"
	printf "${bgreen}#######################################################################${reset}\n"
}

function start_subfunc(){
	notification "${2}" warn
	echo "[ $(date +"%F %T") ] Start subfunction : ${1} " >> "${LOGFILE}"
	start_sub=$(date +%s)
}

function end_subfunc(){
	touch $called_fn_dir/.${2}
	end_sub=$(date +%s)
	getElapsedTime $start_sub $end_sub
	notification "${1} in ${runtime}" good
	echo "[ $(date +"%F %T") ] End subfunction : ${1} " >> "${LOGFILE}"
}

function check_inscope(){
	cat $1 | inscope > $1_tmp && cp $1_tmp $1 && rm -f $1_tmp
}

function resolvers_update(){
	if [ "$generate_resolvers" = true ]; then
		if [ ! "$AXIOM" = true ]; then	
			if [ ! -s "$resolvers" ] || [[ $(find "$resolvers" -mtime +1 -print) ]] ; then
				notification "Resolvers seem older than 1 day\n Generating custom resolvers..." warn
				eval rm -f $resolvers 2>>"$LOGFILE"
				dnsvalidator -tL https://public-dns.info/nameservers.txt -threads $DNSVALIDATOR_THREADS -o $resolvers 2>>"$LOGFILE" >/dev/null
				dnsvalidator -tL https://raw.githubusercontent.com/blechschmidt/massdns/master/lists/resolvers.txt -threads $DNSVALIDATOR_THREADS -o tmp_resolvers 2>>"$LOGFILE" >/dev/null
				[ -s "tmp_resolvers" ] && cat tmp_resolvers | anew -q $resolvers
				[ -s "tmp_resolvers" ] && rm -f tmp_resolvers 2>>"$LOGFILE" >/dev/null
				[ ! -s "$resolvers" ] && wget -q -O - ${resolvers_url} > $resolvers
				[ ! -s "$resolvers_trusted" ] && wget -q -O - ${resolvers_trusted_url} > $resolvers_trusted
				notification "Updated\n" good
	  		fi
		else
			notification "Checking resolvers lists...\n Accurate resolvers are the key to great results\n This may take around 10 minutes if it's not updated" warn
			# shellcheck disable=SC2016
			axiom-exec 'if [ $(find "/home/op/lists/resolvers.txt" -mtime +1 -print) ] || [ $(cat /home/op/lists/resolvers.txt | wc -l) -le 40 ] ; then dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 200 -o /home/op/lists/resolvers.txt ; fi' &>/dev/null
			axiom-exec "wget -q -O - ${resolvers_url} > /home/op/lists/resolvers.txt" 2>>"$LOGFILE" >/dev/null
			axiom-exec "wget -q -O - ${resolvers_trusted_url} > /home/op/lists/resolvers_trusted.txt" 2>>"$LOGFILE" >/dev/null
			notification "Updated\n" good
		fi
		generate_resolvers=false
	else
	
		if  [ ! -s "$resolvers" ] || [[ $(find "$resolvers" -mtime +1 -print) ]] ; then
			notification "Resolvers seem older than 1 day\n Downloading new resolvers..." warn
			wget -q -O - ${resolvers_url} > $resolvers
			wget -q -O - ${resolvers_trusted_url} > $resolvers_trusted
			notification "Resolvers updated\n" good
		fi
	fi
}

function resolvers_update_quick_local(){
	if [ "$update_resolvers" = true ]; then
		wget -q -O - ${resolvers_url} > $resolvers
		wget -q -O - ${resolvers_trusted_url} > $resolvers_trusted
	fi
}

function resolvers_update_quick_axiom(){
	axiom-exec "wget -q -O - ${resolvers_url} > /home/op/lists/resolvers.txt" 2>>"$LOGFILE" >/dev/null
	axiom-exec "wget -q -O - ${resolvers_trusted_url} > /home/op/lists/resolvers_trusted.txt" 2>>"$LOGFILE" >/dev/null
}

function ipcidr_target(){
	IP_CIDR_REGEX='(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?))(\/([8-9]|[1-2][0-9]|3[0-2]))([^0-9.]|$)|(((25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|1?[0-9][0-9]?)$)'
	if [[ $1 =~ ^$IP_CIDR_REGEX ]]; then
		echo $1 | mapcidr -silent | anew -q target_reconftw_ipcidr.txt
		if [ -s "./target_reconftw_ipcidr.txt" ]; then 
			[ "$REVERSE_IP" = true ] && cat ./target_reconftw_ipcidr.txt | hakip2host | cut -d' ' -f 3 | unfurl -u domains 2>/dev/null | sed -e 's/*\.//' -e 's/\.$//' -e '/\./!d' | anew -q ./target_reconftw_ipcidr.txt
			if [[ $(cat ./target_reconftw_ipcidr.txt | wc -l) -eq 1 ]]; then
				domain=$(cat ./target_reconftw_ipcidr.txt)
			elif [[ $(cat ./target_reconftw_ipcidr.txt | wc -l) -gt 1 ]]; then
				unset domain
				list=${PWD}/target_reconftw_ipcidr.txt
			fi
		fi
		if [ -n "$2" ]; then
			cat $list | anew -q $2
			sed -i '/\/[0-9]*$/d' $2
		fi
	fi
}

function axiom_lauch(){
	# let's fire up a FLEET!
	if [ "$AXIOM_FLEET_LAUNCH" = true ] && [ -n "$AXIOM_FLEET_NAME" ] && [ -n "$AXIOM_FLEET_COUNT" ]; then
		start_func ${FUNCNAME[0]} "Launching our Axiom fleet"
		python3 -m pip install --upgrade linode-cli 2>>"$LOGFILE" >/dev/null
		# Check to see if we have a fleet already, if so, SKIP THIS!
		NUMOFNODES=$(timeout 30 axiom-ls | grep -c "$AXIOM_FLEET_NAME")
		if [[ $NUMOFNODES -ge $AXIOM_FLEET_COUNT ]]; then
			axiom-select "$AXIOM_FLEET_NAME*"
			end_func "Axiom fleet $AXIOM_FLEET_NAME already has $NUMOFNODES instances"
		else
			if [[ $NUMOFNODES -eq 0 ]]; then
				startcount=$AXIOM_FLEET_COUNT
			else
				startcount=$((AXIOM_FLEET_COUNT-NUMOFNODES))
			fi
			AXIOM_ARGS=" -i $startcount"
			# Temporarily disabled multiple axiom regions
			# [ -n "$AXIOM_FLEET_REGIONS" ] && axiom_args="$axiom_args --regions=\"$AXIOM_FLEET_REGIONS\" "

			echo "axiom-fleet ${AXIOM_FLEET_NAME} ${AXIOM_ARGS}"
			axiom-fleet ${AXIOM_FLEET_NAME} ${AXIOM_ARGS}
			axiom-select "$AXIOM_FLEET_NAME*"
			if [ -n "$AXIOM_POST_START" ]; then
				eval "$AXIOM_POST_START" 2>>"$LOGFILE" >/dev/null
			fi

			NUMOFNODES=$(timeout 30 axiom-ls | grep -c "$AXIOM_FLEET_NAME" )
			echo "Axiom fleet $AXIOM_FLEET_NAME launched w/ $NUMOFNODES instances" | $NOTIFY
			end_func "Axiom fleet $AXIOM_FLEET_NAME launched w/ $NUMOFNODES instances"
		fi
	fi
}

function axiom_shutdown(){
	if [ "$AXIOM_FLEET_LAUNCH" = true ] && [ "$AXIOM_FLEET_SHUTDOWN" = true ] && [ -n "$AXIOM_FLEET_NAME" ]; then
		#if [ "$mode" == "subs_menu" ] || [ "$mode" == "list_recon" ] || [ "$mode" == "passive" ] || [ "$mode" == "all" ]; then
		if [ "$mode" == "subs_menu" ] || [ "$mode" == "passive" ] || [ "$mode" == "all" ]; then
			notification "Automatic Axiom fleet shutdown is not enabled in this mode" info
			return
		fi
		eval axiom-rm -f "$AXIOM_FLEET_NAME*"
		echo "Axiom fleet $AXIOM_FLEET_NAME shutdown" | $NOTIFY
		notification "Axiom fleet $AXIOM_FLEET_NAME shutdown" info
	fi
}

function axiom_selected(){

	if [[ ! $(axiom-ls | tail -n +2 | sed '$ d' | wc -l) -gt 0 ]]; then
		notification "\n\n${bred} No axiom instances running ${reset}\n\n" error
		exit
	fi

	if [[ ! $(cat ~/.axiom/selected.conf | sed '/^\s*$/d' | wc -l) -gt 0 ]]; then
		notification "\n\n${bred} No axiom instances selected ${reset}\n\n" error
		exit
	fi
}

function start(){

	global_start=$(date +%s)

	if [ "$NOTIFICATION" = true ]; then
		NOTIFY="notify -silent"
	else
	    NOTIFY=""
	fi
	
	printf "\n${bgreen}#######################################################################${reset}"
	notification "Recon succesfully started on ${domain}" good
	[ "$SOFT_NOTIFICATION" = true ] && echo "Recon succesfully started on ${domain}" | notify -silent
	printf "${bgreen}#######################################################################${reset}\n"
	if [ "$upgrade_before_running" = true ]; then
		${SCRIPTPATH}/install.sh --tools
	fi
	tools_installed

	#[[ -n "$domain" ]] && ipcidr_target $domain


	if [ -z "$domain" ]; then
		if [ -n "$list" ]; then
			if [ -z "$domain" ]; then
				domain="Multi"
				dir="$SCRIPTPATH/Recon/$domain"
				called_fn_dir="$dir"/.called_fn
			fi
			if [[ "$list" = /* ]]; then
				install -D "$list" "$dir"/webs/webs.txt
			else
				install -D "$SCRIPTPATH"/"$list" "$dir"/webs/webs.txt
			fi
		fi
	else
		dir="$SCRIPTPATH/Recon/$domain"
		called_fn_dir="$dir"/.called_fn
	fi

	if [ -z "$domain" ]; then
		notification "\n\n${bred} No domain or list provided ${reset}\n\n" error
		exit
	fi

	if [ ! -d "$called_fn_dir" ]; then
		mkdir -p "$called_fn_dir"
	fi
	mkdir -p "$dir"
	cd "$dir"  || { echo "Failed to cd directory in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	if [ "$AXIOM" = true ]; then
		if [ -n "$domain" ]; then
			echo "$domain" | anew -q target.txt
			list="${dir}/target.txt"
		fi
	fi
	mkdir -p .tmp .log osint subdomains webs hosts vulns

	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt
	echo "Start ${NOW} ${NOWT}" > "${LOGFILE}"

	printf "\n"
	printf "${bred} Target: ${domain}\n\n"
}

function end(){

	find $dir -type f -empty -print | grep -v '.called_fn' | grep -v '.log' | grep -v '.tmp' | xargs rm -f 2>>"$LOGFILE" >/dev/null
	find $dir -type d -empty -print -delete 2>>"$LOGFILE" >/dev/null

	echo "End $(date +"%F") $(date +"%T")" >> "${LOGFILE}"

	if [ ! "$PRESERVE" = true ]; then
		find $dir -type f -empty | grep -v "called_fn" | xargs rm -f 2>>"$LOGFILE" >/dev/null
		find $dir -type d -empty | grep -v "called_fn" | xargs rm -rf 2>>"$LOGFILE" >/dev/null
	fi

	if [ "$REMOVETMP" = true ]; then
		rm -rf $dir/.tmp
	fi

    if [ "$REMOVELOG" = true ]; then
            rm -rf $dir/.log
    fi 

	if [ -n "$dir_output" ]; then
		output
		finaldir=$dir_output
	else
		finaldir=$dir
	fi
	#Zip the output folder and send it via tg/discord/slack
	if [ "$SENDZIPNOTIFY" = true ]; then
		zipSnedOutputFolder
	fi
	global_end=$(date +%s)
	getElapsedTime $global_start $global_end
	printf "${bgreen}#######################################################################${reset}\n"
	notification "Finished Recon on: ${domain} under ${finaldir} in: ${runtime}" good
	[ "$SOFT_NOTIFICATION" = true ] && echo "Finished Recon on: ${domain} under ${finaldir} in: ${runtime}" | notify -silent
	printf "${bgreen}#######################################################################${reset}\n"
	#Seperator for more clear messges in telegram_Bot
	echo "******  Stay safe 🦠 and secure 🔐  ******" | $NOTIFY
}

###############################################################################################################
########################################### MODES & MENUS #####################################################
###############################################################################################################

function passive(){
	start
	domain_info
	ip_info
	emails
	google_dorks
	github_dorks
	github_repos
	metadata
	SUBNOERROR=false
	SUBANALYTICS=false
	SUBBRUTE=false
	SUBSCRAPING=false
	SUBPERMUTE=false
	SUBREGEXPERMUTE=false
	SUB_RECURSIVE_BRUTE=false
	WEBPROBESIMPLE=false
	if [ "$AXIOM" = true ]; then
		axiom_lauch
		axiom_selected
	fi

	subdomains_full
	remove_big_files
	favicon
	cdnprovider
	PORTSCAN_ACTIVE=false
	portscan
	
	if [ "$AXIOM" = true ]; then
		axiom_shutdown
	fi

	end
}

function all(){
	start
	recon
	vulns
	end
}

function osint(){
	domain_info
	ip_info
	emails
	google_dorks
	github_dorks
	github_repos
	metadata
	zonetransfer
	favicon
}

function vulns(){
	if [ "$VULNS_GENERAL" = true ]; then
		cors
		open_redirect
		ssrf_checks
		crlf_checks
		lfi
		ssti
		sqli
		xss
		command_injection
		prototype_pollution
		smuggling
		webcache
		spraying
		brokenLinks
		fuzzparams
		4xxbypass
		test_ssl
	fi
}

function multi_osint(){

	global_start=$(date +%s)

	if [ "$NOTIFICATION" = true ]; then
		NOTIFY="notify -silent"
	else
	    NOTIFY=""
	fi

	#[[ -n "$domain" ]] && ipcidr_target $domain

	if [ -s "$list" ]; then
		sed -i 's/\r$//' $list
		targets=$(cat $list)
	else
		notification "Target list not provided" error
		exit
	fi

	workdir=$SCRIPTPATH/Recon/$multi
	mkdir -p $workdir  || { echo "Failed to create directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	cd "$workdir"  || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	mkdir -p .tmp .called_fn osint subdomains webs hosts vulns

	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt
	echo "Start ${NOW} ${NOWT}" > "${LOGFILE}"

	for domain in $targets; do
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		mkdir -p $dir
		cd "$dir"  || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		mkdir -p .tmp .called_fn osint subdomains webs hosts vulns
		NOW=$(date +"%F")
		NOWT=$(date +"%T")
		LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
		touch .log/${NOW}_${NOWT}.txt
		echo "Start ${NOW} ${NOWT}" > "${LOGFILE}"
		domain_info
		ip_info
		emails
		google_dorks
		github_dorks
		github_repos
		metadata
		zonetransfer
		favicon
	done
	cd "$workdir" || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	dir=$workdir
	domain=$multi
	end
}


function recon(){
	domain_info
	ip_info
	zonetransfer

	if [ "$AXIOM" = true ]; then
		axiom_lauch
		axiom_selected
	fi

	subdomains_full
	webprobe_full
	subtakeover
	remove_big_files
	s3buckets
	screenshot
#	virtualhosts
	cdnprovider
#	portscan
	nuclei_check
	fuzz
	urlchecks
	jschecks

	if [ "$AXIOM" = true ]; then
		axiom_shutdown
	fi

	cms_scanner
	url_gf
	wordlist_gen
	wordlist_gen_roboxtractor
	url_ext
}

function multi_recon(){


	global_start=$(date +%s)

	if [ "$NOTIFICATION" = true ]; then
		NOTIFY="notify -silent"
	else
	    NOTIFY=""
	fi

	#[[ -n "$domain" ]] && ipcidr_target $domain

	if [ -s "$list" ]; then
		 sed -i 's/\r$//' $list
		targets=$(cat $list)
	else
		notification "Target list not provided" error
		exit
	fi

	workdir=$SCRIPTPATH/Recon/$multi
	mkdir -p $workdir  || { echo "Failed to create directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	cd "$workdir"  || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }

	mkdir -p .tmp .log .called_fn osint subdomains webs hosts vulns
	NOW=$(date +"%F")
	NOWT=$(date +"%T")
	LOGFILE="${workdir}/.log/${NOW}_${NOWT}.txt"
	touch .log/${NOW}_${NOWT}.txt
	echo "Start ${NOW} ${NOWT}" > "${LOGFILE}"

	[ -n "$flist" ] && LISTTOTAL=$(cat "$flist" | wc -l )

	for domain in $targets; do
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		mkdir -p $dir
		cd "$dir"  || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		mkdir -p .tmp .log .called_fn osint subdomains webs hosts vulns

		NOW=$(date +"%F")
		NOWT=$(date +"%T")
		LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
		touch .log/${NOW}_${NOWT}.txt
		echo "Start ${NOW} ${NOWT}" > "${LOGFILE}"
		loopstart=$(date +%s)

		domain_info
		ip_info
		emails
		google_dorks
		github_dorks
		github_repos
		metadata
		zonetransfer
		favicon
		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen} $domain finished 1st loop in ${runtime}  $currently ${reset}\n"
		if [ -n "$flist" ]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
	done
	cd "$workdir"  || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }

	if [ "$AXIOM" = true ]; then
		axiom_lauch
		axiom_selected
	fi

	for domain in $targets; do
		loopstart=$(date +%s)
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		cd "$dir"  || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		subdomains_full
		webprobe_full
		subtakeover
		remove_big_files
#		virtualhosts
		cdnprovider
#		portscan
		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen} $domain finished 2nd loop in ${runtime}  $currently ${reset}\n"
		if [ -n "$flist" ]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
	done
	cd "$workdir"  || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }

	notification "############################# Total data ############################" info
	NUMOFLINES_users_total=$(find . -type f -name 'users.txt' -exec cat {} + | anew osint/users.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_pwndb_total=$(find . -type f -name 'passwords.txt' -exec cat {} + | anew osint/passwords.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_software_total=$(find . -type f -name 'software.txt' -exec cat {} + | anew osint/software.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_authors_total=$(find . -type f -name 'authors.txt' -exec cat {} + | anew osint/authors.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_subs_total=$(find . -type f -name 'subdomains.txt' -exec cat {} + | anew subdomains/subdomains.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_subtko_total=$(find . -type f -name 'takeover.txt' -exec cat {} + | anew webs/takeover.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_webs_total=$(find . -type f -name 'webs.txt' -exec cat {} + | anew webs/webs.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_webs_total=$(find . -type f -name 'webs_uncommon_ports.txt' -exec cat {} + | anew webs/webs_uncommon_ports.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_ips_total=$(find . -type f -name 'ips.txt' -exec cat {} + | anew hosts/ips.txt | sed '/^$/d' | wc -l)
	NUMOFLINES_cloudsprov_total=$(find . -type f -name 'cdn_providers.txt' -exec cat {} + | anew hosts/cdn_providers.txt | sed '/^$/d' | wc -l)
	find . -type f -name 'portscan_active.txt' -exec cat {} + | tee -a hosts/portscan_active.txt >> "$LOGFILE" 2>&1 >/dev/null
	find . -type f -name 'portscan_active.gnmap' -exec cat {} + | tee hosts/portscan_active.gnmap 2>>"$LOGFILE" >/dev/null
	find . -type f -name 'portscan_passive.txt' -exec cat {} + | tee hosts/portscan_passive.txt 2>&1 >> "$LOGFILE" >/dev/null

	notification "- ${NUMOFLINES_users_total} total users found" good
	notification "- ${NUMOFLINES_pwndb_total} total creds leaked" good
	notification "- ${NUMOFLINES_software_total} total software found" good
	notification "- ${NUMOFLINES_authors_total} total authors found" good
	notification "- ${NUMOFLINES_subs_total} total subdomains" good
	notification "- ${NUMOFLINES_subtko_total} total probably subdomain takeovers" good
	notification "- ${NUMOFLINES_webs_total} total websites" good
	notification "- ${NUMOFLINES_ips_total} total ips" good
	notification "- ${NUMOFLINES_cloudsprov_total} total IPs belongs to cloud" good
	s3buckets
	waf_checks
	nuclei_check
	for domain in $targets; do
		loopstart=$(date +%s)
		dir=$workdir/targets/$domain
		called_fn_dir=$dir/.called_fn
		cd "$dir" || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		loopstart=$(date +%s)
		fuzz
		urlchecks
		jschecks
		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen} $domain finished 3rd loop in ${runtime}  $currently ${reset}\n"
		if [ -n "$flist" ]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
	done

	if [ "$AXIOM" = true ]; then
		axiom_shutdown
	fi

	for domain in $targets; do
		loopstart=$(date +%s)
		dir=$workdir/targets/$domain
        called_fn_dir=$dir/.called_fn 
		cd "$dir" || { echo "Failed to cd directory '$dir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
		cms_scanner
		url_gf
		wordlist_gen
		wordlist_gen_roboxtractor
		url_ext
		currently=$(date +"%H:%M:%S")
		loopend=$(date +%s)
		getElapsedTime $loopstart $loopend
		printf "${bgreen}#######################################################################${reset}\n"
		printf "${bgreen} $domain finished final loop in ${runtime}  $currently ${reset}\n"
		if [ -n "$flist" ]; then
			POSINLIST=$(eval grep -nrE "^$domain$" "$flist" | cut -f1 -d':')
			printf "\n${yellow}  $domain is $POSINLIST of $LISTTOTAL${reset}\n"
		fi
		printf "${bgreen}#######################################################################${reset}\n"
	done
	cd "$workdir" || { echo "Failed to cd directory '$workdir' in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
	dir=$workdir
	domain=$multi
	end
}

function subs_menu(){
	start

	if [ "$AXIOM" = true ]; then
		axiom_lauch
		axiom_selected
	fi

	subdomains_full
	webprobe_full
	subtakeover
	remove_big_files
	screenshot
#	virtualhosts
	zonetransfer
	s3buckets

	if [ "$AXIOM" = true ]; then
		axiom_shutdown
	fi

	end
}

function webs_menu(){
	subtakeover
	remove_big_files
	screenshot
#	virtualhosts
	waf_checks
	nuclei_check
	cms_scanner
	fuzz
	urlchecks
	jschecks
	url_gf
	wordlist_gen
	wordlist_gen_roboxtractor
	url_ext
	vulns
	end
}

function help(){
	printf "\n Usage: $0 [-d domain.tld] [-m name] [-l list.txt] [-x oos.txt] [-i in.txt] "
	printf "\n           	      [-r] [-s] [-p] [-a] [-w] [-n] [-i] [-h] [-f] [--deep] [-o OUTPUT]\n\n"
	printf " ${bblue}TARGET OPTIONS${reset}\n"
	printf "   -d domain.tld     Target domain\n"
	printf "   -m company        Target company name\n"
	printf "   -l list.txt       Targets list (One on each line)\n"
	printf "   -x oos.txt        Exclude subdomains list (Out Of Scope)\n"
	printf "   -i in.txt         Include subdomains list\n"
	printf " \n"
	printf " ${bblue}MODE OPTIONS${reset}\n"
	printf "   -r, --recon       Recon - Perform full recon process (without attacks)\n"
	printf "   -s, --subdomains  Subdomains - Perform Subdomain Enumeration, Web probing and check for sub-tko\n"
	printf "   -p, --passive     Passive - Perform only passive steps\n"
	printf "   -a, --all         All - Perform all checks and active exploitations\n"
	printf "   -w, --web         Web - Perform web checks from list of subdomains\n"
	printf "   -n, --osint       OSINT - Check for public intel data\n"
	printf "   -c, --custom      Custom - Launches specific function against target, u need to know the function name first\n"
	printf "   -h                Help - Show help section\n"
	printf " \n"
	printf " ${bblue}GENERAL OPTIONS${reset}\n"
	printf "   --deep            Deep scan (Enable some slow options for deeper scan)\n"
	printf "   -f config_file    Alternate reconftw.cfg file\n"
	printf "   -o output/path    Define output folder\n"
	printf "   -v, --vps         Axiom distributed VPS \n"
	printf "   -q                Rate limit in requests per second \n"
	printf " \n"
	printf " ${bblue}USAGE EXAMPLES${reset}\n"
	printf " ${byellow}Perform full recon (without attacks):${reset}\n"
	printf " ./reconftw.sh -d example.com -r\n"
	printf " \n"
	printf " ${byellow}Perform subdomain enumeration on multiple targets:${reset}\n"
	printf " ./reconftw.sh -l targets.txt -s\n"
	printf " \n"
	printf " ${byellow}Perform Web based scanning on a subdomains list:${reset}\n"
	printf " ./reconftw.sh -d example.com -l targets.txt -w\n"
	printf " \n"
	printf " ${byellow}Multidomain recon:${reset}\n"
	printf " ./reconftw.sh -m company -l domainlist.txt -r\n"
	printf " \n"
	printf " ${byellow}Perform full recon (with active attacks) along Out-Of-Scope subdomains list:${reset}\n"
	printf " ./reconftw.sh -d example.com -x out.txt -a\n"
	printf " \n"
	printf " ${byellow}Perform full recon and store output to specified directory:${reset}\n"
	printf " ./reconftw.sh -d example.com -r -o custom/path\n"
	printf " \n"
	printf " ${byellow}Run custom function:${reset}\n"
	printf " ./reconftw.sh -d example.com -c nuclei_check \n"
	printf " \n"
	printf " ${byellow}Start the web server:${reset}\n"
	printf " ./reconftw.sh --web-server start\n"
	printf " \n"
	printf " ${byellow}Stop the web server:${reset}\n"
	printf " ./reconftw.sh --web-server stop\n"
}

###############################################################################################################
############################################# WEB SERVER ######################################################
###############################################################################################################

# webserver initialization, thanks @lur1el, @d3vchac, @mx61tt and @dd4n1b0y <3


function webserver(){
	printf "${bgreen} Web Interface    by @lur1el, @d3vchac, @mx61tt and @dd4n1b0y ${reset}\n"
	ver=$(python3 -V 2>&1 | sed 's/.* \([0-9]\).\([0-9]\).*/\1\2/')
	
    if [ "$ver" -lt "31" ]; then
        echo "The web interface requires python 3.10 or greater"
        exit 1
    fi

	if [ "$1" == "start" ]; then
		ipAddress=$(curl -s ifconfig.me) 

		if [ "$ipAddress" != "" ]; then
			printf "\n ${bblue}Starting web server... ${reset}\n"
			cd $SCRIPTPATH/web || { echo "Failed to cd to $dir in ${FUNCNAME[0]} @ line ${LINENO}"; exit 1; }
			$SUDO source $SCRIPTPATH/web/.venv/bin/activate
			$SUDO screen -S ReconftwWebserver -X kill &>/dev/null
			$SUDO screen -dmS ReconftwWebserver python3 manage.py runserver $ipAddress:8001 &>/dev/null
			$SUDO service redis-server start &>/dev/null
			$SUDO screen -S ReconftwCelery -X kill &>/dev/null
			$SUDO screen -dmS ReconftwCelery python3 -m celery -A web worker -l info -P prefork -Q run_scans,default &>/dev/null
			printf " ${bblue}Web server started! ${reset}\n"
			printf " ${bblue}Service Address: http://$ipAddress:8001${reset}\n"
		else
			printf "\n"
			printf " ${red}Server IP address not found.${reset}\n"
			printf "\n"
			printf " ${bblue}Check if the server has internet connection.${reset}\n"
		fi
	elif [ "$1" == "stop" ]; then
		printf "\n ${bblue}Stoping web server... ${reset}\n"
		# $SUDO service postgresql stop
		$SUDO screen -S ReconftwWebserver -X kill &>/dev/null
		$SUDO service redis-server stop &>/dev/null
		$SUDO screen -S ReconftwCelery -X kill &>/dev/null
		printf " ${bblue}Web server stoped! ${reset}\n"
	else
		printf "\n"
		printf " ${red}Invalid action${reset}\n"
		printf "\n"
		printf " ${bblue}Valid actions: start/stop${reset}\n"
	fi
}

###############################################################################################################
########################################### START SCRIPT  #####################################################
###############################################################################################################

# macOS PATH initialization, thanks @0xtavian <3
if [[ "$OSTYPE" == "darwin"* ]]; then
	PATH="/usr/local/opt/gnu-getopt/bin:$PATH"
	PATH="/usr/local/opt/coreutils/libexec/gnubin:$PATH"
fi

PROGARGS=$(getopt -o 'd:m:l:x:i:o:f:q:c:rspanwvh::' --long 'domain:,list:,recon,subdomains,passive,all,web,osint,deep,web-server,help,vps' -n 'reconFTW' -- "$@")


# Note the quotes around "$PROGARGS": they are essential!
eval set -- "$PROGARGS"
unset PROGARGS

while true; do
    case "$1" in
        '-d'|'--domain')
            domain=$2
			ipcidr_target $2
            shift 2
            continue
            ;;
        '-m')
            multi=$2
            shift 2
            continue
            ;;
        '-l'|'--list')
			list=$2
			for t in $(cat $list); do
				ipcidr_target $t $list
			done
            shift 2
            continue
            ;;
        '-x')
            outOfScope_file=$2
            shift 2
            continue
            ;;
        '-i')
            inScope_file=$2
            shift 2
            continue
            ;;

        # modes
        '-r'|'--recon')
            opt_mode='r'
            shift
            continue
            ;;
        '-s'|'--subdomains')
            opt_mode='s'
            shift
            continue
            ;;
        '-p'|'--passive')
            opt_mode='p'
            shift
            continue
            ;;
        '-a'|'--all')
            opt_mode='a'
            shift
            continue
            ;;
        '-w'|'--web')
            opt_mode='w'
            shift
            continue
            ;;
        '-n'|'--osint')
            opt_mode='n'
            shift
            continue
            ;;
		'-c'|'--custom')
			custom_function=$2
			opt_mode='c'
            shift 2
            continue
            ;;
        # extra stuff
        '-o')
			if [[ "$2" != /* ]]; then
            	dir_output=$PWD/$2
			else
				dir_output=$2
			fi
            shift 2
            continue
            ;;
		'-v'|'--vps')
			which axiom-ls &>/dev/null || { printf "\n Axiom is needed for this mode and is not installed \n You have to install it manually \n" && exit; allinstalled=false;}
			AXIOM=true
            shift
            continue
            ;;
        '-f')
			CUSTOM_CONFIG=$2
            shift 2
            continue
            ;;
		'-q')
			rate_limit=$2
            shift 2
            continue
            ;;
        '--deep')
            opt_deep=true
            shift
            continue
            ;;

        '--')
			shift
			break
		    ;;
        '--web-server')
            . ./reconftw.cfg
			banner
			webserver $3
			exit 1
		    ;;
        '--help'| '-h'| *)
            # echo "Unknown argument: $1"
            . ./reconftw.cfg
			banner
            help
			tools_installed
			exit 1
		    ;;
    esac
done

# This is the first thing to do to read in alternate config
SCRIPTPATH="$( cd "$(dirname "$0")" >/dev/null 2>&1 || exit ; pwd -P )"
. "$SCRIPTPATH"/reconftw.cfg || { echo "Error importing reconftw.ctg"; exit 1; }
if [ -s "$CUSTOM_CONFIG" ]; then
# shellcheck source=/home/six2dez/Tools/reconftw/custom_config.cfg
. "${CUSTOM_CONFIG}" || { echo "Error importing reconftw.ctg"; exit 1; }
fi

if [ $opt_deep ]; then
    DEEP=true
fi

if [ $rate_limit ]; then
    NUCLEI_RATELIMIT=$rate_limit
	FFUF_RATELIMIT=$rate_limit
	HTTPX_RATELIMIT=$rate_limit
fi

if [ -n "$outOfScope_file" ]; then
    isAsciiText $outOfScope_file
    if [ "False" = "$IS_ASCII" ]
    then
        printf "\n\n${bred} Out of Scope file is not a text file${reset}\n\n"
        exit
    fi
fi

if [ -n "$inScope_file" ]; then
    isAsciiText $inScope_file
    if [ "False" = "$IS_ASCII" ]
    then
        printf "\n\n${bred} In Scope file is not a text file${reset}\n\n"
        exit
    fi
fi

if [[ $(id -u | grep -o '^0$') == "0" ]]; then
    SUDO=" "
else
    SUDO="sudo"
fi

startdir=${PWD}

banner

check_version

startdir=${PWD}
if [ -n "$list" ]; then
	if [[ "$list" = ./* ]]; then
		flist="${startdir}/${list:2}"
	elif [[ "$list" = ~* ]]; then
		flist="${HOME}/${list:2}"
	elif [[ "$list" = /* ]]; then
		flist=$list
	else
		flist="$startdir/$list"
	fi
else
	flist=''
fi

case $opt_mode in
        'r')
            if [ -n "$multi" ];	then
				if [ "$AXIOM" = true ]; then
					mode="multi_recon"
				fi
				multi_recon
				exit
			fi
			if [ -n "$list" ]; then
				if [ "$AXIOM" = true ]; then
					mode="list_recon"
				fi
				sed -i 's/\r$//' $list
				for domain in $(cat $list); do
					start
					recon
					end
				done
			else
				if [ "$AXIOM" = true ]; then
					mode="recon"
				fi
				start
				recon
				end
			fi
            ;;
        's')
            if [ -n "$list" ]; then
				if [ "$AXIOM" = true ]; then
					mode="subs_menu"
				fi
				sed -i 's/\r$//' $list
				for domain in $(cat $list); do
					subs_menu
				done
			else
				subs_menu
			fi
            ;;
        'p')
            if [ -n "$list" ]; then
				if [ "$AXIOM" = true ]; then
					mode="passive"
				fi
				sed -i 's/\r$//' $list
				for domain in $(cat $list); do
					passive
				done
			else
				passive
			fi
            ;;
        'a')
			export VULNS_GENERAL=true
            if [ -n "$list" ]; then
				if [ "$AXIOM" = true ]; then
					mode="all"
				fi
				sed -i 's/\r$//' $list
				for domain in $(cat $list); do
					all
				done
			else
				all
			fi
            ;;
        'w')
			if [ -n "$list" ]; then
				start
				if [[ "$list" = /* ]]; then
					cp $list $dir/webs/webs.txt
				else
					cp $SCRIPTPATH/$list $dir/webs/webs.txt
				fi
			else
				printf "\n\n${bred} Web mode needs a website list file as target (./reconftw.sh -l target.txt -w) ${reset}\n\n"
				exit
			fi
			webs_menu
			exit
            ;;
        'n')
			PRESERVE=true
			if [ -n "$multi" ];	then
				multi_osint
				exit
			fi
			if [ -n "$list" ]; then
				sed -i 's/\r$//' $list
				while IFS= read -r domain; do
					start
					osint
					end
				done
			else
				start
				osint
				end
			fi
			;;
		'c')
			export DIFF=true
			dir="$SCRIPTPATH/Recon/$domain"
			cd $dir || { echo "Failed to cd directory '$dir'"; exit 1; }
			LOGFILE="${dir}/.log/${NOW}_${NOWT}.txt"
			called_fn_dir=$dir/.called_fn 
			$custom_function
			cd $SCRIPTPATH || { echo "Failed to cd directory '$dir'"; exit 1; }
			exit
            ;;
        # No mode selected.  EXIT!
		*)
            help
            tools_installed
            exit 1
            ;;
esac

