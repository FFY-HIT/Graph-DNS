#!/bin/bash

# ==============================================
# GraphDNS 两阶段完整性能测试脚本
# 阶段1: preprocess 生成 ZoneRecord.facts
# 阶段2: graph_verifier 读取 ZoneRecord.facts 并验证
# ==============================================

set -o pipefail

# 配置参数
PREPROCESS_PROGRAM="./preprocess"
VERIFY_PROGRAM="./graph_verifier"

# 数据集路径
DATA_DIR="../census"

# 记录数配置数组
RECORD_COUNTS=(100000 200000 300000 400000 500000
               600000 700000 800000 900000 1000000
               1500000 2000000 2500000 3000000
               3500000 4000000 4500000 5000000
               6000000 7000000 8000000 9000000 10000000)

# 每组重复次数
REPEAT_TIMES=5

# 输出文件
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="performance_results_${TIMESTAMP}.csv"
SUMMARY_FILE="performance_summary_${TIMESTAMP}.csv"
LOG_FILE="performance_log_${TIMESTAMP}.txt"

# 临时文件
FACT_FILE="ZoneRecord.facts"
VERIFY_TIME_FILE=".verify_time_tmp"
PREPROCESS_OUTPUT_FILE=".preprocess_output_tmp"
VERIFY_OUTPUT_FILE=".verify_output_tmp"

# 日志函数
log() {
    local message="$1"
    local timestamp
    timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] $message" | tee -a "$LOG_FILE"
}

echo "=============================================="
log "开始 GraphDNS 两阶段性能测试"
log "预处理程序: $PREPROCESS_PROGRAM"
log "验证程序: $VERIFY_PROGRAM"
log "数据目录: $DATA_DIR"
log "记录数组数: ${#RECORD_COUNTS[@]} 组"
log "每组重复: $REPEAT_TIMES 次"
log "输出文件: $RESULTS_FILE"
log "摘要文件: $SUMMARY_FILE"
log "日志文件: $LOG_FILE"
echo "=============================================="

# 检查程序是否存在
if [ ! -f "$PREPROCESS_PROGRAM" ]; then
    log "错误: 预处理程序 $PREPROCESS_PROGRAM 不存在!"
    log "请先编译: g++ -O3 -std=c++17 -fopenmp preprocess.cpp -o preprocess"
    exit 1
fi

if [ ! -f "$VERIFY_PROGRAM" ]; then
    log "错误: 验证程序 $VERIFY_PROGRAM 不存在!"
    log "请先编译: g++ -O3 -std=c++17 graph_verifier.cpp -o graph_verifier"
    exit 1
fi

# 检查可执行权限
if [ ! -x "$PREPROCESS_PROGRAM" ]; then
    log "错误: $PREPROCESS_PROGRAM 没有执行权限"
    log "可执行: chmod +x $PREPROCESS_PROGRAM"
    exit 1
fi

if [ ! -x "$VERIFY_PROGRAM" ]; then
    log "错误: $VERIFY_PROGRAM 没有执行权限"
    log "可执行: chmod +x $VERIFY_PROGRAM"
    exit 1
fi

# 检查数据目录是否存在
if [ ! -d "$DATA_DIR" ]; then
    log "错误: 数据目录 $DATA_DIR 不存在!"
    exit 1
fi

# 检查依赖
if ! command -v bc > /dev/null 2>&1; then
    log "错误: bc 未安装，无法计算平均值"
    log "Ubuntu: sudo apt-get install bc"
    exit 1
fi

if [ ! -x /usr/bin/time ]; then
    log "错误: /usr/bin/time 不存在，无法统计验证时间"
    exit 1
fi

# 创建结果文件并写入表头
echo "max_records,run_num,preprocess_time,verify_time,total_time,error_count,edge_count,fact_size_mb" > "$RESULTS_FILE"

# 创建摘要文件并写入表头
echo "max_records,avg_preprocess_time,avg_verify_time,avg_total_time,min_total_time,max_total_time,avg_error_count,avg_edge_count,avg_fact_size_mb" > "$SUMMARY_FILE"

# 计算总实验次数
TOTAL_EXPERIMENTS=$(( ${#RECORD_COUNTS[@]} * REPEAT_TIMES ))
log "总实验次数: $TOTAL_EXPERIMENTS"

TOTAL_START_TIME=$(date +%s)
EXPERIMENTS_COMPLETED=0

# 清理上次残留
rm -f "$VERIFY_TIME_FILE" "$PREPROCESS_OUTPUT_FILE" "$VERIFY_OUTPUT_FILE"

for record_count in "${RECORD_COUNTS[@]}"; do
    log ""
    log "=================================================="
    log "测试记录数: $record_count"
    log "=================================================="

    CURRENT_PREPROCESS_TIMES=()
    CURRENT_VERIFY_TIMES=()
    CURRENT_TOTAL_TIMES=()
    CURRENT_ERROR_COUNTS=()
    CURRENT_EDGE_COUNTS=()
    CURRENT_FACT_SIZES=()

    GROUP_START_TIME=$(date +%s)

    for ((run=1; run<=REPEAT_TIMES; run++)); do
        EXPERIMENTS_COMPLETED=$((EXPERIMENTS_COMPLETED + 1))

        log "运行 $run/$REPEAT_TIMES (总进度: $EXPERIMENTS_COMPLETED/$TOTAL_EXPERIMENTS)..."

        # 清理上一轮输出，避免 graph_verifier 读取旧 facts 或统计旧结果
        rm -f "$FACT_FILE" Error.tsv GraphEdge.tsv "$VERIFY_TIME_FILE" "$PREPROCESS_OUTPUT_FILE" "$VERIFY_OUTPUT_FILE"

        # -----------------------------
        # 阶段1: preprocess
        # -----------------------------
        PREPROCESS_OUTPUT=$("$PREPROCESS_PROGRAM" "$DATA_DIR" "$record_count" 2>&1)
        PREPROCESS_EXIT_CODE=$?

        echo "$PREPROCESS_OUTPUT" > "$PREPROCESS_OUTPUT_FILE"
        echo "$PREPROCESS_OUTPUT" >> "$LOG_FILE"

        if [ $PREPROCESS_EXIT_CODE -ne 0 ]; then
            log "  错误: preprocess 运行失败，退出码 $PREPROCESS_EXIT_CODE"
            continue
        fi

        if [ ! -f "$FACT_FILE" ]; then
            log "  错误: preprocess 没有生成 $FACT_FILE"
            continue
        fi

        PREPROCESS_TIME=$(echo "$PREPROCESS_OUTPUT" | grep "Loaded" | grep -Eo "in [0-9.]+s" | grep -Eo "[0-9.]+" | head -1)

        if [ -z "$PREPROCESS_TIME" ]; then
            log "  错误: 无法提取 preprocess 时间"
            echo "$PREPROCESS_OUTPUT" | grep -E "(Loaded|Output|Processing|Scanning|Error|Warning)" >> "$LOG_FILE"
            continue
        fi

        # facts 文件大小，单位 MB
        FACT_SIZE_MB=$(du -m "$FACT_FILE" | awk '{print $1}')

        # -----------------------------
        # 阶段2: graph_verifier
        # -----------------------------
        /usr/bin/time -f "%e" -o "$VERIFY_TIME_FILE" "$VERIFY_PROGRAM" "$FACT_FILE" > "$VERIFY_OUTPUT_FILE" 2>&1
        VERIFY_EXIT_CODE=$?

        cat "$VERIFY_OUTPUT_FILE" >> "$LOG_FILE"

        if [ $VERIFY_EXIT_CODE -ne 0 ]; then
            log "  错误: graph_verifier 运行失败，退出码 $VERIFY_EXIT_CODE"
            continue
        fi

        if [ ! -f "$VERIFY_TIME_FILE" ]; then
            log "  错误: 未生成验证时间文件 $VERIFY_TIME_FILE"
            continue
        fi

        VERIFY_TIME=$(cat "$VERIFY_TIME_FILE" | tail -n 1)

        if [ -z "$VERIFY_TIME" ]; then
            log "  错误: 无法提取 graph_verifier 验证时间"
            continue
        fi

        # 统计 Error.tsv 和 GraphEdge.tsv 行数，扣除表头
        if [ -f "Error.tsv" ]; then
            ERROR_COUNT=$(($(wc -l < Error.tsv) - 1))
            if [ "$ERROR_COUNT" -lt 0 ]; then ERROR_COUNT=0; fi
        else
            ERROR_COUNT=0
        fi

        if [ -f "GraphEdge.tsv" ]; then
            EDGE_COUNT=$(($(wc -l < GraphEdge.tsv) - 1))
            if [ "$EDGE_COUNT" -lt 0 ]; then EDGE_COUNT=0; fi
        else
            EDGE_COUNT=0
        fi

        TOTAL_TIME=$(echo "$PREPROCESS_TIME + $VERIFY_TIME" | bc)

        CURRENT_PREPROCESS_TIMES+=("$PREPROCESS_TIME")
        CURRENT_VERIFY_TIMES+=("$VERIFY_TIME")
        CURRENT_TOTAL_TIMES+=("$TOTAL_TIME")
        CURRENT_ERROR_COUNTS+=("$ERROR_COUNT")
        CURRENT_EDGE_COUNTS+=("$EDGE_COUNT")
        CURRENT_FACT_SIZES+=("$FACT_SIZE_MB")

        echo "$record_count,$run,$PREPROCESS_TIME,$VERIFY_TIME,$TOTAL_TIME,$ERROR_COUNT,$EDGE_COUNT,$FACT_SIZE_MB" >> "$RESULTS_FILE"

        log "  预处理: ${PREPROCESS_TIME}s, 验证: ${VERIFY_TIME}s, 总计: ${TOTAL_TIME}s"
        log "  Error: $ERROR_COUNT, GraphEdge: $EDGE_COUNT, Facts: ${FACT_SIZE_MB}MB"

        # 进度估计
        ELAPSED=$(( $(date +%s) - TOTAL_START_TIME ))
        AVG_TIME_PER_EXPERIMENT=$(echo "scale=2; $ELAPSED / $EXPERIMENTS_COMPLETED" | bc)
        REMAINING_EXPERIMENTS=$((TOTAL_EXPERIMENTS - EXPERIMENTS_COMPLETED))
        REMAINING_TIME=$(echo "$AVG_TIME_PER_EXPERIMENT * $REMAINING_EXPERIMENTS" | bc | awk '{printf "%d", $1}')

        PROGRESS_PERCENT=$((EXPERIMENTS_COMPLETED * 100 / TOTAL_EXPERIMENTS))

        ELAPSED_READABLE=$(printf "%02d:%02d:%02d" $((ELAPSED/3600)) $(((ELAPSED%3600)/60)) $((ELAPSED%60)))
        REMAINING_READABLE=$(printf "%02d:%02d:%02d" $((REMAINING_TIME/3600)) $(((REMAINING_TIME%3600)/60)) $((REMAINING_TIME%60)))

        log "  进度: $PROGRESS_PERCENT% | 已用: $ELAPSED_READABLE | 预计剩余: $REMAINING_READABLE"
    done

    # -----------------------------
    # 当前 record_count 统计
    # -----------------------------
    if [ ${#CURRENT_TOTAL_TIMES[@]} -gt 0 ]; then
        log ""
        log "计算统计信息..."

        PREPROCESS_SUM=0
        VERIFY_SUM=0
        TOTAL_SUM=0
        ERROR_SUM=0
        EDGE_SUM=0
        FACT_SUM=0

        NUM_VALID_RUNS=${#CURRENT_TOTAL_TIMES[@]}

        MIN_TOTAL=${CURRENT_TOTAL_TIMES[0]}
        MAX_TOTAL=${CURRENT_TOTAL_TIMES[0]}

        for ((i=0; i<${#CURRENT_TOTAL_TIMES[@]}; i++)); do
            PREPROCESS_SUM=$(echo "$PREPROCESS_SUM + ${CURRENT_PREPROCESS_TIMES[$i]}" | bc)
            VERIFY_SUM=$(echo "$VERIFY_SUM + ${CURRENT_VERIFY_TIMES[$i]}" | bc)
            TOTAL_SUM=$(echo "$TOTAL_SUM + ${CURRENT_TOTAL_TIMES[$i]}" | bc)
            ERROR_SUM=$(echo "$ERROR_SUM + ${CURRENT_ERROR_COUNTS[$i]}" | bc)
            EDGE_SUM=$(echo "$EDGE_SUM + ${CURRENT_EDGE_COUNTS[$i]}" | bc)
            FACT_SUM=$(echo "$FACT_SUM + ${CURRENT_FACT_SIZES[$i]}" | bc)

            if (( $(echo "${CURRENT_TOTAL_TIMES[$i]} < $MIN_TOTAL" | bc -l) )); then
                MIN_TOTAL=${CURRENT_TOTAL_TIMES[$i]}
            fi

            if (( $(echo "${CURRENT_TOTAL_TIMES[$i]} > $MAX_TOTAL" | bc -l) )); then
                MAX_TOTAL=${CURRENT_TOTAL_TIMES[$i]}
            fi
        done

        AVG_PREPROCESS=$(echo "scale=4; $PREPROCESS_SUM / $NUM_VALID_RUNS" | bc)
        AVG_VERIFY=$(echo "scale=4; $VERIFY_SUM / $NUM_VALID_RUNS" | bc)
        AVG_TOTAL=$(echo "scale=4; $TOTAL_SUM / $NUM_VALID_RUNS" | bc)
        AVG_ERROR=$(echo "scale=2; $ERROR_SUM / $NUM_VALID_RUNS" | bc)
        AVG_EDGE=$(echo "scale=2; $EDGE_SUM / $NUM_VALID_RUNS" | bc)
        AVG_FACT=$(echo "scale=2; $FACT_SUM / $NUM_VALID_RUNS" | bc)

        GROUP_ELAPSED=$(( $(date +%s) - GROUP_START_TIME ))
        GROUP_ELAPSED_READABLE=$(printf "%02d:%02d:%02d" $((GROUP_ELAPSED/3600)) $(((GROUP_ELAPSED%3600)/60)) $((GROUP_ELAPSED%60)))

        log "组 $record_count 完成! 耗时: $GROUP_ELAPSED_READABLE"
        log "有效运行次数: $NUM_VALID_RUNS"
        log "平均预处理时间: ${AVG_PREPROCESS}s"
        log "平均验证时间: ${AVG_VERIFY}s"
        log "平均总时间: ${AVG_TOTAL}s"
        log "总时间范围: ${MIN_TOTAL}s - ${MAX_TOTAL}s"
        log "平均 Error 数: ${AVG_ERROR}"
        log "平均 GraphEdge 数: ${AVG_EDGE}"
        log "平均 Facts 大小: ${AVG_FACT}MB"

        echo "$record_count,$AVG_PREPROCESS,$AVG_VERIFY,$AVG_TOTAL,$MIN_TOTAL,$MAX_TOTAL,$AVG_ERROR,$AVG_EDGE,$AVG_FACT" >> "$SUMMARY_FILE"
    else
        log "警告: 组 $record_count 没有有效数据，跳过统计"
    fi
done

# 总耗时
TOTAL_ELAPSED=$(( $(date +%s) - TOTAL_START_TIME ))
TOTAL_ELAPSED_READABLE=$(printf "%02d:%02d:%02d" $((TOTAL_ELAPSED/3600)) $(((TOTAL_ELAPSED%3600)/60)) $((TOTAL_ELAPSED%60)))

log ""
log "=============================================="
log "测试完成!"
log "总耗时: $TOTAL_ELAPSED_READABLE"
log "结果文件: $RESULTS_FILE"
log "摘要文件: $SUMMARY_FILE"
log "日志文件: $LOG_FILE"
log "=============================================="

echo ""
echo "=============================================="
echo "最终报告"
echo "=============================================="
echo ""

if [ -f "$SUMMARY_FILE" ]; then
    echo "摘要统计 (每组平均值):"
    echo "-----------------------------------------------------------------------------------------------"
    printf "%-12s %-14s %-12s %-12s %-12s %-12s %-12s %-12s %-12s\n" \
        "记录数" "预处理(s)" "验证(s)" "总计(s)" "最小(s)" "最大(s)" "Error" "Edge" "Facts(MB)"
    echo "-----------------------------------------------------------------------------------------------"

    tail -n +2 "$SUMMARY_FILE" | while IFS=',' read -r rec avg_pre avg_verify avg_total min_total max_total avg_error avg_edge avg_fact; do
        printf "%-12s %-14.4f %-12.4f %-12.4f %-12.4f %-12.4f %-12.2f %-12.2f %-12.2f\n" \
            "$rec" "$avg_pre" "$avg_verify" "$avg_total" "$min_total" "$max_total" "$avg_error" "$avg_edge" "$avg_fact"
    done

    echo "-----------------------------------------------------------------------------------------------"
    echo ""

    echo "关键数据点:"
    echo "-----------"

    KEY_POINTS=(100000 500000 1000000 2000000 3000000 5000000 10000000)
    for point in "${KEY_POINTS[@]}"; do
        grep "^$point," "$SUMMARY_FILE" | while IFS=',' read -r rec avg_pre avg_verify avg_total min_total max_total avg_error avg_edge avg_fact; do
            echo "$point 条记录:"
            echo "  预处理时间: ${avg_pre}s"
            echo "  验证时间: ${avg_verify}s"
            echo "  总时间: ${avg_total}s"
            echo "  时间范围: ${min_total}s - ${max_total}s"
            echo "  Error 数: ${avg_error}"
            echo "  GraphEdge 数: ${avg_edge}"
            echo "  Facts 大小: ${avg_fact}MB"
            echo ""
        done
    done
fi

echo ""
echo "文件位置:"
echo "---------"
echo "详细结果: $(pwd)/$RESULTS_FILE"
echo "统计摘要: $(pwd)/$SUMMARY_FILE"
echo "运行日志: $(pwd)/$LOG_FILE"

# 生成 gnuplot 图表
if command -v gnuplot > /dev/null 2>&1; then
    echo ""
    echo "生成图表..."

    cat > plot_performance.gnuplot << EOF
set terminal pngcairo size 1400,900 enhanced font 'Arial,10'
set output 'performance_chart.png'

set datafile separator ","
set multiplot layout 2,2 title "GraphDNS Two-Stage Performance" font 'Arial,14'

set title "Total Time vs Records"
set xlabel "Records"
set ylabel "Time (s)"
set logscale x
set grid
plot '$SUMMARY_FILE' using 1:4 with linespoints lw 2 title 'Avg Total Time'

set title "Preprocessing vs Verification"
set xlabel "Records"
set ylabel "Time (s)"
set logscale x
set grid
plot '$SUMMARY_FILE' using 1:2 with linespoints lw 2 title 'Preprocessing', \
     '$SUMMARY_FILE' using 1:3 with linespoints lw 2 title 'Verification'

set title "Time Range"
set xlabel "Records"
set ylabel "Time (s)"
set logscale x
set grid
plot '$SUMMARY_FILE' using 1:5 with linespoints lw 2 title 'Min Total', \
     '$SUMMARY_FILE' using 1:4 with linespoints lw 2 title 'Avg Total', \
     '$SUMMARY_FILE' using 1:6 with linespoints lw 2 title 'Max Total'

set title "Stage Proportion"
set xlabel "Records"
set ylabel "Proportion"
set logscale x
set yrange [0:1]
set grid
plot '$SUMMARY_FILE' using 1:(\$2/\$4) with linespoints lw 2 title 'Preprocessing Ratio', \
     '$SUMMARY_FILE' using 1:(\$3/\$4) with linespoints lw 2 title 'Verification Ratio'

unset multiplot
EOF

    gnuplot plot_performance.gnuplot
    echo "图表已保存为: $(pwd)/performance_chart.png"
else
    echo ""
    echo "提示: 安装 gnuplot 可以生成性能图表:"
    echo "  Ubuntu: sudo apt-get install gnuplot"
    echo "  Mac: brew install gnuplot"
    echo "  CentOS: sudo yum install gnuplot"
fi

# 清理临时文件
rm -f "$VERIFY_TIME_FILE" "$PREPROCESS_OUTPUT_FILE" "$VERIFY_OUTPUT_FILE"

echo ""
echo "=============================================="
echo "测试脚本执行完成!"
echo "=============================================="