# Copyright 2026 AlphaOne LLC
# SPDX-License-Identifier: Apache-2.0
import copy
import unittest
import graph_baseline as baseline

class BaselineTests(unittest.TestCase):
    def records(self):
        return [dict(operation=operation,engine=engine,rows=rows,nodes=1024,
                     edges=1023,warmup=10,samples_us=list(range(1,201)))
                for (operation,engine),rows in baseline.EXPECTED.items()]

    def test_nearest_rank_percentiles_use_raw_samples(self):
        result=baseline.summarize(self.records())
        self.assertEqual(len(result),9)
        for row in result:
            self.assertEqual((row['n'],row['p50_us'],row['p95_us'],row['p99_us']),(200,100,190,198))
        data=self.records();data[0]['samples_us'].reverse()
        self.assertEqual(baseline.summarize(data)[0],result[0])

    def test_incomplete_or_duplicate_scenario_cannot_publish(self):
        baseline.summarize(self.records())
        for data in [[],self.records()[:-1],self.records()+[self.records()[0]]]:
            with self.subTest(count=len(data)),self.assertRaises(baseline.Failure):
                baseline.summarize(data)

    def test_empty_wrong_count_and_invalid_samples_cannot_publish(self):
        baseline.summarize(self.records())
        for key,value in [('rows',0),('nodes',0),('edges',0),('warmup',0),('samples_us',[]),('samples_us',[0]*200),('samples_us',[True]*200),('samples_us',[float('nan')]*200)]:
            data=copy.deepcopy(self.records());data[0][key]=value
            with self.subTest(key=key),self.assertRaises(baseline.Failure):
                baseline.summarize(data)

if __name__=='__main__':unittest.main()
