# get all results
total_pages=$1
rm -rf logs/
mkdir -p logs
sleep $(($RANDOM % 200 + 100))
node parser.js --page_count 1 --start_page 1 --out logs/1.dat 
cat logs/1.dat > all.dat
for (( i=2; i<=$1; i++))
do
    sleep $(($RANDOM % 200 + 100))
    node parser.js --page_count 1 --start_page $i --out logs/$i.dat  --wo_headers
    cat logs/$i.dat >> all.dat
done
