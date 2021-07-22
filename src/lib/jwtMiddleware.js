import jwt from 'jsonwebtoken';
import User from '../models/user';

const jwtMiddleware = async (ctx, next) => {
  const token = ctx.cookies.get('access_token');
  if (!token) return next(); // 토큰이 없음
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    ctx.state.user = {
      _id: decoded._id,
      username: decoded.username,
    };
    // 토큰의 남은 유효 기간이 3.5일 미만이면 재발급
    const now = Math.floor(Date.now() / 1000);
    // Date.now은 1970년 1월 1일 0시 0분 0초부터 현재까지 경과된 밀리 초를 반환
    // 1000으로 나누어주면 초 단위로 변환됨 (1초 -> 1000밀리초)
    // decoded 객체에는 iat(생성시간), exp(만료시간)이 있음, 토큰 유효 시간을 7일로 두면 실제로 두 시간의 차를
    // 분(/60), 시(/60), 하루(/24)로 나누면 7이 나오는 걸 확인할 수 있다.
    if (decoded.exp - now < 60 * 60 * 24 * 3.5) {
      console.log('재발급');
      const user = await User.findById(decoded._id);
      const token = user.generateToken();
      ctx.cookies.set('access_token', token, {
        maxAge: 1000 * 60 * 60 * 24 * 7, // 7일
        httpOnly: true,
      });
    }
    return next();
  } catch (e) {
    // 토큰 검증 실패
    return next();
  }
};

export default jwtMiddleware;
