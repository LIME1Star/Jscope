from jscope.analyzers.base import Analyzer


class Boom(Analyzer):
    name = "boom"

    def analyze_project(self, ctx):
        raise RuntimeError("kaboom")


ANALYZERS = [Boom]
