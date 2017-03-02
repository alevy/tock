d = read.csv('interrupt_benchmarks.csv')
d$experiment = factor(d$experiment, c("rnsp", "rslp", "noisr", "minisr", "rbuf"))
plot(d)

