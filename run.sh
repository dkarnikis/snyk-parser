# get all results
total_pages=$1
rm -rf logs/
mkdir -p logs
node parser.js --page_count 5 --start_page 1 --out logs/1.dat 
cat logs/1.dat > all.dat
count=2
for (( i=6; i<=$1+5; i=i+5))
do
    sleep $((200 + $RANDOM % 40))
    node parser.js --page_count 5 --start_page $i --out logs/$count.dat  --wo_headers
    cat logs/$count.dat >> all.dat
    count=$((count + 1))
done
